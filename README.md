# 民俗活动影像的人员授权与跨渠道撤回

原片记录可识别人员的区间，剪辑记录引用片段和适用场景。人物编号是临时演练编号。发布及撤回的对端回执以已交付的成品编号区分。

`fixtures/registers.json` 提供演练台账，`fixtures/events.ndjson` 提供各端送达的独立消息，`fixtures/receipts.json` 提供合作方的模拟回执。事件游标为送达顺序。业务发生时点出现在消息内容中时，以其来源所注明的时点为准。整套资料均为合成数据。

## 本地联调

使用 Python 3.11.2 标准库。联调入口只监听本地地址，不需要账号或外部连接。

```sh
python3 -m unittest -v
python3 fixture_gateway.py --port 8765
```

`GET /v1/registers` 返回台账。用 `GET /v1/events?after=0&limit=50` 读取一页消息，后续页将上一页的 `next_cursor` 作为 `after`。每条消息有 `cursor`、`source`、`minute` 及原业务记录 `payload`。

对端发送协议为 `POST /v1/receipts`，正文提供 `reference`、`operation`、`recipient`，三个字段均为字符串。需要配对的操作与接收方见回执示例文件。返回对象含 `reference` 和对端 `receipt`。若条目设置 `lost_reply`，首次调用被记录后连接断开。可用 `GET /v1/receipts/<reference>` 查看已记录的回执。相同编号和内容可重试，编号被另一个操作使用时返回 409。

联调进程运行期间保存回执记录。需要试读其他台账、消息与回执时，可通过 `--fixtures` 指向另一组同名资料文件。合作方只返回模拟事实，业务办理功能由各方应用负责。

## 授权与撤回后端

`rights/` 包在原联调入口之外提供可复用的业务后端，只依赖标准库。

```sh
python3 -m unittest -v          # 现有联调桩 + 业务后端测试
python3 -m rights --port 8766   # 可选：业务后端的本地 HTTP 入口
```

### 代码结构

| 模块 | 职责 |
| --- | --- |
| `rights/service.py` | `RightsService`：登记、送审、审核、发布、撤回、追收、转载申报 |
| `rights/analysis.py` | 纯函数：原片区间、画面人物、遮挡后仍可见的区间、授权时窗 |
| `rights/registers.py` | 台账载入（`registers.json`） |
| `rights/transport.py` | 对端回执：内存桩与 `fixture_gateway.py` 的 HTTP 实现 |
| `rights/security.py` | 角色与渠道可见范围 |
| `rights/web.py` | 可选的 HTTP 适配层 |
| `rights/demo.py` | 按演练资料构造服务、回放消息 |

### 办理流程

1. **编辑** 登记原片区间与人物，提交成品所引用的原片区间送审；`create_version`
   每次产生一个新的版本编号，`editor_brief` 只返回审片需要的授权范围（人物编号、
   用途、时窗、区间），不含身份材料。
2. **审片** 按版本注记每个片段里的人物；可为本次审到的片段确认遮挡范围。
   `approve_review` 把记录绑定到该版本的内容指纹，并把“有未认清人物”的审核标为
   仅供内部。只审了部分片段时，其余含人物的片段不能当作已审。
3. **发布** 每次发布登记交付编号、渠道、版本与父交付。逐人逐用途核对基础授权；
   县级转载许可（`delivery_scope`）限定来源、去向、成品、版本、用途与是否允许
   再转递；合作馆曾单独取得的同用途许可（`direct_permissions`）只对该渠道和该
   版本有效。未认清人物的审核不得发布到公共渠道。
4. **撤回** 一次撤回只终止被指名授权的那一种用途。`impact(person)` 按版本分别
   给出“已由可信审查遮住，可继续”“仍露出该人物，需暂停或追收”，并按交付链给
   出责任人（发布方、上游渠道、审片人）。
5. **对端处置** `plan_revocation` 为需要暂停或追收的交付生成处置请求，`send_all`
   按回执事实更新渠道状态；回执未达时沿用同一编号重试。`confirm_revocation`
   由县级账号确认并从根交付沿链追到实际转载端。`report_parcel` 分别核对转载端
   申报的已收回副本、仍展示版本与独立许可；`record_forward` 登记未按约定再转
   递的副本去向，便于追收。
6. **编辑重新送审** 新版本不会继承旧版本的发布状态；`edit_history` 仍保留原稿、
   旧审核、交付与撤回经过。

### 演练资料的关键判断

* `mix-b` 已完成可信遮挡审查（`verified_masks`），其中 `p-3` 被完全遮住；由它
  换成的静帧 `mix-b-still` 是另一个版本，不能沿用该审查。
* `p-3` 撤回 `highlights` 后，`internal` 用途的授权仍然有效；`mix-a` 的
  `county-feed` 交付暂停新分发，经 `museum-feed`、`festival-feed` 的副本按交付
  编号追收。
* `museum-feed` 对 `p-3` 有单独许可，但只限 `mix-b`，不能拿来覆盖 `mix-a`。
* 回执示例里 `museum-feed` 的 `lost_reply`：首次发送只更新为“待回执”，用同
  一编号重试会取回“已收到但未下线”的事实。

HTTP 适配层用请求头 `X-Role`（`editor`/`reviewer`/`rights`/`publication`/
`county`/`channel`/`partner`/`auditor`）和可选的 `X-Actor`、`X-Channel` 表示
调用方；渠道角色只能读取与处置交给自己的交付。
