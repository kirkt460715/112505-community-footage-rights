"""业务后端的行为测试。

用例对应演练里的几条硬要求：
编辑送审、人物授权审核、合作方发布、按人物撤回追影响与责任人。
"""

import json
from datetime import timedelta
import unittest

from rights import RightsService
from rights.clock import FixedClock
from rights.demo import build_service, load_events, replay_fixture
from rights.errors import Conflict, Forbidden, NotFound, ValidationError
from rights.model import Role
from rights.security import Actor

EDITOR = Actor(Role.EDITOR, "editor-1")
REVIEWER = Actor(Role.REVIEWER, "reviewer-1")
PUBLISHER = Actor(Role.PUBLICATION, "publisher-1")
RIGHTS = Actor(Role.RIGHTS, "rights-1")
COUNTY = Actor(Role.COUNTY, "county-1")


def channel(name):
    return Actor(Role.CHANNEL, f"{name}-ops", channel=name)


class ReviewTest(unittest.TestCase):
    def setUp(self):
        self.service = build_service()

    def approve(self, edit="mix-a", scope=None, persons=None, version=None):
        review = self.service.submit_review(edit, version=version, scope=scope, actor=EDITOR)
        version_record = self.service._version(edit, version)
        for index in review["scope_indices"]:
            self.service.annotate(
                review["id"],
                index,
                (persons or {}).get(index, self._known_persons(version_record, index)),
                actor=REVIEWER,
            )
        return self.service.approve_review(review["id"], actor=REVIEWER)

    def _known_persons(self, version, index):
        return list(self.service._span_persons(version, index))

    def test_review_is_bound_to_the_submitted_version(self):
        approved = self.approve("mix-b")
        self.assertEqual(approved["state"], "approved")
        self.service.create_version(
            "mix-b", kind="still", uses=["highlights"],
            spans=[["clip-1", 1500, 2700]], version="mix-b-still",
            derived_from="mix-b", actor=EDITOR,
        )
        with self.assertRaises(Conflict) as caught:
            self.service.publish(
                "mix-b", "museum-feed", version="mix-b-still", delivery="d-20",
                at="2028-10-03T00:10:00+00:00", actor=PUBLISHER,
            )
        self.assertEqual(caught.exception.code, "review_required")

    def test_old_review_does_not_survive_into_replacement_versions(self):
        first = self.approve("mix-a")
        self.assertTrue(first["trusted"])
        self.service.create_version(
            "mix-a", kind="still", uses=["highlights"],
            spans=[["clip-1", 1500, 2700]], version="mix-a-still", actor=EDITOR,
        )
        history = self.service.edit_history("mix-a", actor=EDITOR)
        self.assertEqual(history["current_version"], "mix-a-still")
        original = next(r for r in history["reviews"] if r["id"] == first["id"])
        self.assertEqual(original["state"], "approved")
        self.assertEqual(original["version"], "mix-a")

    def test_partial_scope_leaves_unreviewed_person_spans_unpublishable(self):
        review = self.service.submit_review("mix-a", scope=[0], actor=EDITOR)
        self.service.annotate(review["id"], 0, ["p-3", "p-7"], actor=REVIEWER)
        self.service.approve_review(review["id"], actor=REVIEWER)
        check = self.service.review_scope_check(review["id"])
        self.assertEqual(check["unreviewed_person_spans"], [1])
        self.assertFalse(check["publishable"])
        with self.assertRaises(Conflict) as caught:
            self.service.publish(
                "mix-a", "county-feed", delivery="d-30",
                at="2028-10-03T00:10:00+00:00", actor=PUBLISHER,
            )
        self.assertEqual(caught.exception.code, "review_scope_incomplete")

    def test_mask_only_covers_the_reviewed_segment(self):
        review = self.service.submit_review("mix-a", scope=[0], actor=EDITOR)
        self.service.annotate(review["id"], 0, ["p-3", "p-7"], actor=REVIEWER)
        self.service.add_mask(review["id"], "p-3", 0, 1000, 3000, actor=REVIEWER)
        with self.assertRaises(ValidationError):
            self.service.add_mask(review["id"], "p-3", 1, 0, 2200, actor=REVIEWER)
        with self.assertRaises(ValidationError):
            self.service.add_mask(review["id"], "p-3", 0, 900, 3000, actor=REVIEWER)

    def test_unknown_person_review_stays_internal(self):
        review = self.service.submit_review("draft-c", actor=EDITOR)
        self.service.annotate(review["id"], 0, [], recognized=False, actor=REVIEWER)
        approved = self.service.approve_review(review["id"], actor=REVIEWER)
        self.assertTrue(approved["internal_only"])
        with self.assertRaises(Forbidden) as caught:
            self.service.publish(
                "draft-c", "county-feed", use="poster", delivery="d-31",
                at="2028-10-03T00:10:00+00:00", actor=PUBLISHER,
            )
        self.assertEqual(caught.exception.code, "internal_only_review")

    def test_editor_brief_has_no_identity_material(self):
        brief = self.service.editor_brief("mix-a", actor=EDITOR)
        text = json.dumps(brief, ensure_ascii=False)
        self.assertIn("p-3", text)
        for marker in ("id_card", "phone", "address", "identity"):
            self.assertNotIn(marker, text.lower())
        self.assertNotIn("channels", brief["items"][0])


class PublishingTest(unittest.TestCase):
    def setUp(self):
        self.service = replay_fixture()
        review = self.service.submit_review("mix-a", actor=EDITOR)
        self.service.annotate(review["id"], 0, ["p-3", "p-7"], actor=REVIEWER)
        self.service.annotate(review["id"], 1, ["p-7"], actor=REVIEWER)
        self.service.approve_review(review["id"], actor=REVIEWER)

    def test_publication_requires_authorization_for_each_use(self):
        review = self.service.submit_review("draft-c", actor=EDITOR)
        self.service.annotate(review["id"], 0, ["p-3"], actor=REVIEWER)
        self.service.approve_review(review["id"], actor=REVIEWER)
        with self.assertRaises(Forbidden) as caught:
            self.service.publish(
                "draft-c", "county-feed", use="poster", delivery="d-40",
                at="2028-10-03T00:05:00+00:00", actor=PUBLISHER,
            )
        self.assertEqual(caught.exception.code, "authorization_missing")

    def test_onward_delivery_needs_a_scope(self):
        with self.assertRaises(Forbidden) as caught:
            self.service.publish(
                "mix-a", "festival-feed", parent_delivery="d-07", delivery="d-41",
                at="2028-10-03T00:20:00+00:00", actor=PUBLISHER,
            )
        self.assertEqual(caught.exception.code, "onward_not_permitted")

    def test_scope_is_limited_to_version_and_channels(self):
        with self.assertRaises(Forbidden):
            self.service.publish(
                "mix-a", "county-feed", parent_delivery="d-07", delivery="d-42",
                at="2028-10-03T00:20:00+00:00", actor=PUBLISHER,
            )
        scope = self.service.grant_delivery_scope(
            "county-feed", "museum-feed", "mix-a", "highlights",
            version="mix-a", can_forward=False, actor=COUNTY,
        )
        self.assertEqual(scope["version"], "mix-a")
        self.assertFalse(scope["can_forward"])

    def test_granted_scope_applies_only_to_named_version_and_target(self):
        granted = self.service.grant_delivery_scope(
            "county-feed", "museum-feed", "mix-a", "highlights",
            version="mix-a", can_forward=False, actor=COUNTY,
        )
        allowed = self.service.publish(
            "mix-a", "museum-feed", parent_delivery="d-08", delivery="d-44",
            at="2028-10-03T00:20:00+00:00", actor=PUBLISHER,
        )
        self.assertIn(allowed["authorized_scope"], {granted["id"], "scope:1"})
        with self.assertRaises(Forbidden):
            self.service.publish(
                "mix-a", "festival-feed", parent_delivery="d-08", delivery="d-45",
                at="2028-10-03T00:20:00+00:00", actor=PUBLISHER,
            )

    def test_forwarding_needs_can_forward_on_the_upstream_scope(self):
        self.service.grant_delivery_scope(
            "county-feed", "museum-feed", "mix-a", "highlights",
            version="mix-a", can_forward=False, actor=COUNTY,
        )
        self.service.publish(
            "mix-a", "museum-feed", parent_delivery="d-08", delivery="d-46",
            at="2028-10-03T00:20:00+00:00", actor=PUBLISHER,
        )
        with self.assertRaises(Forbidden):
            self.service.publish(
                "mix-a", "festival-feed", parent_delivery="d-46", delivery="d-47",
                at="2028-10-03T00:21:00+00:00", actor=PUBLISHER,
            )
        self.service.grant_delivery_scope(
            "museum-feed", "festival-feed", "mix-a", "highlights",
            version="mix-a", can_forward=False, actor=COUNTY,
        )
        allowed = self.service.publish(
            "mix-a", "festival-feed", parent_delivery="d-46", delivery="d-48",
            at="2028-10-03T00:21:00+00:00", actor=PUBLISHER,
        )
        self.assertEqual(allowed["authorized_scope"],
                         "scope:museum-feed:festival-feed:mix-a:3")

    def test_internal_delivery_does_not_need_public_clearance(self):
        review = self.service.submit_review("mix-a", actor=EDITOR)
        self.service.annotate(review["id"], 0, ["p-3", "p-7"], actor=REVIEWER)
        self.service.annotate(review["id"], 1, ["p-7"], actor=REVIEWER)
        self.service.approve_review(review["id"], actor=REVIEWER)
        version = self.service.create_version(
            "mix-a", kind="video", uses=["internal"],
            spans=[["clip-1", 1000, 6000], ["clip-2", 0, 2200]],
            version="mix-a-internal", actor=EDITOR,
        )
        internal = self.service.submit_review(
            "mix-a", version=version["version"], actor=EDITOR
        )
        self.service.annotate(internal["id"], 0, ["p-3", "p-7"], actor=REVIEWER)
        self.service.annotate(internal["id"], 1, ["p-7"], actor=REVIEWER)
        self.service.approve_review(internal["id"], actor=REVIEWER)
        published = self.service.publish(
            "mix-a", "internal-kiosk", version="mix-a-internal", use="internal",
            delivery="d-43", at="2028-10-03T00:15:00+00:00", actor=PUBLISHER,
        )
        self.assertEqual(published["id"], "d-43")


class RevocationTest(unittest.TestCase):
    def setUp(self):
        self.service = replay_fixture()

    def test_only_the_named_use_is_revoked(self):
        self.service.revoke(
            authorization="p-3-base", use="highlights",
            at="2028-10-03T00:29:00+00:00", actor=RIGHTS,
        )
        later = self.service.clock.now() + timedelta(hours=1)
        self.assertTrue(self.service._base_permission("p-3", "internal", later))
        self.assertEqual(self.service._base_permission("p-3", "highlights", later), [])

    def test_impact_separates_masked_continue_from_recall(self):
        impact = self.service.impact("p-3", actor=RIGHTS)
        self.assertEqual(impact["recall"], ["d-07", "d-11"])
        self.assertEqual(impact["hold"], ["d-08"])
        mix_b = next(v for v in impact["versions"] if v["version"] == "mix-b")
        self.assertTrue(mix_b["masked"])
        self.assertEqual(mix_b["review_id"], "seed-mix-b-mix-b")
        mix_b_still = next(v for v in impact["versions"] if v["version"] == "mix-b-still")
        self.assertFalse(mix_b_still["masked"], "换用静帧不能沿用视频的遮挡审查")

    def test_responsible_parties_are_traceable(self):
        impact = self.service.impact("p-3", actor=RIGHTS)
        self.assertEqual(impact["responsible"]["publishers"]["county-feed"], ["fixture"])
        self.assertEqual(impact["responsible"]["received_from"]["museum-feed"], ["county-feed"])

    def test_receipts_drive_channel_states_and_survive_lost_reply(self):
        plan = self.service.plan_revocation("rev-0001", actor=RIGHTS)
        self.assertEqual({r["channel"] for r in plan["requests"]},
                         {"county-feed", "museum-feed", "festival-feed"})
        first = {r["channel"]: r for r in self.service.send_all(actor=PUBLISHER)}
        self.assertEqual(first["county-feed"]["status"], "acknowledged")
        self.assertEqual(first["festival-feed"]["receipt"]["down"], True)
        self.assertEqual(first["museum-feed"]["status"], "sent_pending_reply")
        self.assertEqual(self.service.get_delivery("d-08", actor=PUBLISHER)["state"], "recalled")
        retried = {r["channel"]: r for r in self.service.send_all(actor=PUBLISHER)}
        self.assertEqual(retried["museum-feed"]["status"], "acknowledged_still_displayed")
        self.assertEqual(retried["museum-feed"]["attempts"], 2)
        self.assertEqual(retried["museum-feed"]["reference"],
                         first["museum-feed"]["reference"])
        self.assertEqual(self.service.get_delivery("d-07", actor=PUBLISHER)["state"],
                         "still_displayed")

    def test_county_confirmation_traces_downstream_recipients(self):
        self.service.plan_revocation("rev-0001", actor=RIGHTS)
        self.service.send_all(actor=PUBLISHER)
        confirmed = self.service.confirm_revocation("rev-0001", channel="county-feed",
                                                    actor=COUNTY)
        chains = {entry["delivery"]: entry["chain"] for entry in confirmed["traced"]}
        self.assertEqual(chains["d-11"], ["d-08", "d-07", "d-11"])

    def test_county_confirmation_works_without_prior_plan(self):
        confirmed = self.service.confirm_revocation("rev-0001", channel="county-feed",
                                                    actor=COUNTY)
        self.assertEqual(
            {entry["delivery"] for entry in confirmed["traced"]},
            {"d-08", "d-07", "d-11"},
        )
        self.assertTrue(all(r["status"] == "planned" for r in confirmed["requests"]))

    def test_channel_only_sees_its_own_deliveries(self):
        view = self.service.channel_view("museum-feed", actor=channel("museum-feed"))
        self.assertEqual([d["id"] for d in view["deliveries"]], ["d-07"])
        with self.assertRaises(Forbidden):
            self.service.channel_view("museum-feed", actor=channel("county-feed"))
        with self.assertRaises(Forbidden):
            self.service.get_delivery("d-07", actor=channel("county-feed"))

    def test_editing_resubmission_keeps_original_and_recall_history(self):
        original = self.service.edit_history("mix-a", actor=EDITOR)
        self.service.create_version(
            "mix-a", kind="still", uses=["highlights"],
            spans=[["clip-1", 2000, 2500]], version="mix-a-v2", actor=EDITOR,
        )
        later = self.service.edit_history("mix-a", actor=EDITOR)
        self.assertEqual([v["version"] for v in later["versions"]], ["mix-a", "mix-a-v2"])
        self.assertEqual(later["revocations"], original["revocations"])
        self.assertEqual(
            {d["id"] for d in later["deliveries"]}, {"d-08", "d-07", "d-11"}
        )


class ParcelReportTest(unittest.TestCase):
    def setUp(self):
        self.service = replay_fixture()
        self.museum = channel("museum-feed")

    def test_claim_checks_three_things_separately(self):
        result = self.service.report_parcel(
            "d-07", "museum-feed", copies_withdrawn=True, still_displayed=["mix-b"],
            independent_license={
                "person": "p-3", "channel": "museum-feed",
                "version": "mix-b", "use": "highlights",
            },
            at="2028-10-03T01:00:00+00:00", actor=self.museum,
        )
        items = {f["item"]: f for f in result["findings"]}
        self.assertEqual(items["copies_withdrawn"]["action"], "none")
        self.assertEqual(items["still_displayed"]["action"], "none")
        self.assertEqual(items["independent_license"]["valid"], True)
        self.assertFalse(result["needs_recall"])

    def test_unlicensed_displayed_version_must_be_recalled(self):
        result = self.service.report_parcel(
            "d-07", "museum-feed", copies_withdrawn=True, still_displayed=["mix-a"],
            at="2028-10-03T01:00:00+00:00", actor=self.museum,
        )
        self.assertTrue(result["needs_recall"])
        self.assertEqual(self.service.get_delivery("d-07", actor=PUBLISHER)["state"],
                         "still_displayed")

    def test_unauthorized_forward_is_logged_with_destination(self):
        copy = self.service.record_forward(
            "d-07", "mall-screen-3", detail="未按约定转发",
            at="2028-10-03T02:00:00+00:00", actor=COUNTY,
        )
        self.assertEqual(copy["destination"], "mall-screen-3")
        self.assertEqual(copy["status"], "to_recall")
        self.assertIn("mall-screen-3",
                      [c["destination"] for c in self.service.list_unauthorized_copies()])


class EventTest(unittest.TestCase):
    def test_replay_is_idempotent(self):
        service = replay_fixture()
        before = json.dumps(service.snapshot(), sort_keys=True, ensure_ascii=False)
        service.ingest_events(load_events())
        after = json.dumps(service.snapshot(), sort_keys=True, ensure_ascii=False)
        self.assertEqual(before, after)

    def test_reused_cursor_with_different_content_conflicts(self):
        service = replay_fixture()
        event = load_events()[0]
        with self.assertRaises(Conflict):
            service.ingest_event({**event, "payload": {**event["payload"], "state": "other"}})

    def test_published_at_wins_over_delivery_minute(self):
        service = replay_fixture()
        delivery = service.get_delivery("d-07", actor=PUBLISHER)
        self.assertEqual(delivery["published_at"], "2028-10-03T00:25:00+00:00")
        self.assertEqual(delivery["received_at"], "2028-10-03T00:33:00+00:00")


class HttpTest(unittest.TestCase):
    """可选的 HTTP 适配层与角色裁剪。"""

    @classmethod
    def setUpClass(cls):
        from http.client import HTTPConnection
        from threading import Thread

        from rights.web import RightsServer

        cls.service = replay_fixture()
        cls.server = RightsServer(0, cls.service)
        cls.thread = Thread(
            target=cls.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        cls.thread.start()
        cls.http = HTTPConnection

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def call(self, method, path, payload=None, role="auditor", channel=None):
        connection = self.http("127.0.0.1", self.server.server_port, timeout=3)
        try:
            headers = {"Content-Type": "application/json", "X-Role": role}
            if channel:
                headers["X-Channel"] = channel
            body = None if payload is None else json.dumps(payload)
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_impact_endpoint(self):
        status, body = self.call("GET", "/v1/impact?person=p-3", role="rights")
        self.assertEqual(status, 200)
        self.assertEqual(body["recall"], ["d-07", "d-11"])

    def test_channel_cannot_read_another_channel(self):
        self.assertEqual(
            self.call("GET", "/v1/channels?channel=museum-feed",
                      role="channel", channel="museum-feed")[0],
            200,
        )
        self.assertEqual(
            self.call("GET", "/v1/channels?channel=museum-feed",
                      role="channel", channel="county-feed")[0],
            403,
        )

    def test_editor_cannot_revoke(self):
        status, body = self.call(
            "POST", "/v1/revocations", {"person": "p-7", "use": "highlights"}, role="editor"
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "forbidden")

    def test_unknown_route_is_rejected(self):
        self.assertEqual(self.call("GET", "/v2/nope")[0], 400)


if __name__ == "__main__":
    unittest.main()
