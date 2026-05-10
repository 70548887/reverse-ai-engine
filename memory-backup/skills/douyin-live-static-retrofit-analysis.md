---
name: douyin-live-static-retrofit-analysis
description: Static workflow for enumerating Douyin/TikTok live webcast Retrofit endpoints from decompiled smali, extracting method boundaries/signatures, and producing reusable JSON/Markdown summaries before ADB/runtime validation.
---

# Douyin Live Static Retrofit Analysis

Use this when analyzing Douyin live-room APIs from a decompiled APK/smali tree, especially when the user wants the static interface/protocol chain mapped before phone/ADB validation.

## Workflow

1. **Locate decompiled smali root**
   - Common path in this environment: `/opt/data/home/reverse-tools/douyin_decompiled/douyin_base`.
   - Verify it contains `smali_classes*` directories before scanning.

2. **Scan Retrofit interface annotations**
   - Search `.smali` files for `/webcast/` endpoint strings.
   - For each hit, find enclosing `.method` ... `.end method` bounds.
   - Capture:
     - endpoint string from `value = "/webcast/..."`
     - HTTP annotation from `Lcom/bytedance/retrofit2/http/{GET,POST,Streaming,...};`
     - method signature line
     - file path and method start/end line numbers
     - class declaration line

3. **Prioritize live core endpoints**
   Focus first on:
   - `/webcast/room/pre_enter/`
   - `/webcast/room/enter/`
   - `/webcast/room/enter_backend/`
   - `/webcast/room/enter_preload/`
   - `/webcast/room/info/`
   - `/webcast/room/info_by_scene/`
   - `/webcast/room/info_by_user/`
   - `/webcast/room/mget_info/`
   - `/webcast/room/live_room_id/`
   - `/webcast/room/leave/`
   - `/webcast/im/heartbeat/`
   - `/webcast/im/send_sync_stream_info/`
   - `/webcast/room/digg/`
   - `/webcast/room/like/`
   - `/webcast/gift/*`

4. **Expected key files**
   These often contain the main boundaries:
   - `smali_classes15/com/bytedance/android/livesdk/chatroom/api/RoomRetrofitApi.smali`
   - `smali_classes15/com/bytedance/android/livesdk/chatroom/room/api/RoomManagementRetrofitApi.smali`
   - `smali_classes11/com/bytedance/android/live/broadcast/preview/api/StartLiveApi.smali`
   - `smali_classes15/com/ss/android/ugc/aweme/live/pre/LivePreEnterLeaveApi.smali`
   - `smali_classes15/com/bytedance/android/livesdk/interactivity/like/DiggApi.smali`
   - `smali_classes11/com/bytedance/android/live/effect/sticker/api/LiveEffectApi.smali`

5. **Write artifacts**
   Save machine-readable and human-readable outputs under an analysis directory, e.g.:
   - `/opt/data/home/reverse-tools/douyin_analysis/douyin_live_core_endpoints.json`
   - `/opt/data/home/reverse-tools/douyin_analysis/douyin_live_core_summary.md`

6. **Summarize signatures**
   Convert smali descriptor types for readability:
   - `J` → `long`
   - `I` → `int`
   - `Z` → `boolean`
   - `Ljava/lang/String;` → `String`
   - `Ljava/util/HashMap;` → `HashMap`
   - `Ljava/util/Map;` → `Map`
   - return types are often `Observable`, `Call`, or `Single`

7. **Next static step**
   After endpoint enumeration, backtrack call sites to recover request field construction, especially `HashMap`/`Map` parameters and request model objects such as `SyncStreamInfoReqBean`.

8. **Backtrack `Map` / `HashMap` request fields from call sites**
   - Search for direct Retrofit invocations such as:
     - `RoomManagementRetrofitApi;->enterRoom(...Ljava/util/Map;...)`
     - `RoomRetrofitApi;->fetchRoom(Ljava/util/HashMap;)`
     - `RoomManagementRetrofitApi;->leaveRoom(JLjava/util/HashMap;)`
   - Read ~150-300 lines before the invocation and track the register passed as the map argument.
    - Common patterns observed in Douyin live-room code:
     - `GenerateApiMap` → `putIfNotNull(key, value)` → `getMap()` is often the request `Map` for `enterRoom` / backend-room style calls.
     - Plain `new HashMap` + `LX/0cdc;->LLLIILIL(map, key, value)` is a field insertion helper.
     - `fetchRoom` may have multiple minimal builders; examples observed:
       - `X/0UMX.smali`: `Room.getId()` → `String.valueOf(J)` → `put("room_id", value)`.
       - `X/0ZBr.smali`: fields are `room_id` from `this.LJ`, `pack_level="4"`, optional `from_type="2"` when `BaseRoomFetcher.isVSEndType`, optional `live_distribution_scene` from `BaseRoomFetcher.LIZLLL`.
     - `LX/0ZCG;->LJIIIIZZ(Bundle, String, String, String)` builds an enter/backend `Map` with `enter_source` from p2, `enter_type` from p1, `is_login` from `IMiddlewareUserCenter.isLogin()` as `"1"/"0"`, `live_reason` from p3, and optional `live_distribution_scene` from `Bundle.getString("live_distribution_scene")`.
     - After enter/backend map creation, `LX/0ZCG;->LJII(...)` can add `traffic_tags` from `MiddlewareLiveLogger -> PageSourceLog filter -> IMiddlewarePageFilter.getAnchorIdentity()` unless disabled by `LIVE_DISABLE_ENTER_ACHOR_IDENTITY_PARAM`.
     - `leaveRoom` uses a local `HashMap`; in `X/0ZCG.smali` the explicit field seen was `leave_frame_time`, computed from room timing / `DataCenter` helper state before `RoomManagementRetrofitApi.leaveRoom(J, HashMap)`. The value can be `"-1"` when the method boolean argument and room helper state are true; otherwise it is derived from `Room.startTime + LX/0ZCJ.LIZ(DataCenter)` when available. Confirm the exact `LLLIILIL(map, key, value)` register flow before listing it as a submitted request field.
   - For `enterRoom`, first verify whether the map comes from `LX/0ZCG;->LJIIIIZZ(Bundle, String, String, String)` or an inline duplicated `GenerateApiMap` block. Confirm source parameters before summarizing fields. Also check post-construction mutations before the Retrofit call (e.g. `traffic_tags`, `chunk_sleep_ms` on backend variants).
- Record not just field names, but value provenance: method parameter, `Bundle` key, `DataCenter` key, logger filter, settings flag, or `Room` model getter.

## Pitfalls

- When backtracking request maps, distinguish **DataCenter/model reads used for branch decisions** from **fields actually inserted into the HashMap/Map passed to Retrofit**. In `X/0ZCG.leaveRoom`, `data_room` and `data_audience_pre_linkmic_waiting` are read from `DataCenter`, but they are not necessarily submitted as `/webcast/room/leave/` request fields unless there is an explicit `HashMap.put` / `LX/0cdc;->LLLIILIL(vMap, key, value)` on the same map register before the Retrofit call.
- Do not rely only on raw grep output; large endpoint scans truncate easily. Write JSON to disk and summarize from it.
- The same endpoint can have multiple Retrofit interfaces, overloads, or flow-specific variants. Use the tuple `(endpoint, file path, method signature)` for identity.
- Some Retrofit methods may lack a plain `GET`/`POST` annotation in the simple parser or may include `Streaming`; preserve unknown/empty HTTP values rather than dropping the method.
- Static endpoint mapping is not runtime verification. Label summaries as static until validated by hooks, logs, or traffic capture.

## Verification

- Read back the generated Markdown summary after writing it.
- Read back the generated/updated JSON as well, especially the `param_names`, `http` annotations, and any added provenance/static-source fields for `enterRoom`, `fetchRoom`, `leaveRoom`, `preEnterRoom`, and `heartbeat`.
- Run explicit consistency checks before closing the artifact-update task: count remaining `http: null` entries, empty `param_names: []`, and mismatches between JSON endpoint fields and Markdown field-source tables. Clear or deliberately explain any remaining anomalies.
- When updating analysis artifacts mid-task, only mark the final summary/update task complete after both JSON and Markdown have been re-read and checked for consistency; context compaction or tool-call limits can otherwise leave `t5c`-style artifact-update tasks in an in-progress state.
- Confirm task list items are complete only after both JSON and Markdown artifacts exist.
- If counts look suspiciously small, broaden from exact room/im/gift filters to all `/webcast/` Retrofit annotations and then re-filter.
