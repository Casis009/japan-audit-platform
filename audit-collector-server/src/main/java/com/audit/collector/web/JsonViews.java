package com.audit.collector.web;

import com.audit.collector.model.IngestRequest;
import com.audit.collector.model.LogView;
import com.audit.collector.service.ChainAnchorService;
import com.audit.collector.store.AuditStore;

import java.util.List;

import static com.audit.collector.json.MiniJson.quote;

/** API レスポンスの JSON 組み立て（文字列はすべて MiniJson.quote でエスケープ）。 */
final class JsonViews {

    private JsonViews() {
    }

    static String logs(List<LogView> logs) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < logs.size(); i++) {
            LogView l = logs.get(i);
            if (i > 0) sb.append(',');
            sb.append('{')
              .append("\"chainSeq\":").append(l.chainSeq()).append(',')
              .append("\"traceId\":").append(quote(l.traceId())).append(',')
              .append("\"timestamp\":").append(quote(l.timestamp().toString())).append(',')
              .append("\"systemCode\":").append(quote(l.systemCode())).append(',')
              .append("\"clientIp\":").append(quote(l.clientIp())).append(',')
              .append("\"userId\":").append(quote(l.userId())).append(',')
              .append("\"httpMethod\":").append(quote(l.httpMethod())).append(',')
              .append("\"requestUri\":").append(quote(l.requestUri())).append(',')
              .append("\"httpStatus\":").append(l.httpStatus()).append(',')
              .append("\"executionTimeMs\":").append(l.executionTimeMs()).append(',')
              .append("\"piiOccurrences\":").append(l.piiOccurrences()).append(',')
              .append("\"myNumberPersonCount\":").append(l.myNumberPersonCount()).append(',')
              .append("\"alertLevel\":").append(quote(l.alertLevel())).append(',')
              .append("\"alertReason\":").append(quote(l.alertReason())).append(',')
              .append("\"recordHash\":").append(quote(l.recordHash())).append(',')
              .append("\"details\":[");
            List<IngestRequest.Detail> ds = l.details();
            for (int j = 0; j < ds.size(); j++) {
                IngestRequest.Detail d = ds.get(j);
                if (j > 0) sb.append(',');
                sb.append("{\"piiType\":").append(quote(d.piiType()))
                  .append(",\"maskedValue\":").append(quote(d.maskedValue()))
                  .append(",\"occurredIn\":").append(quote(d.occurredIn()))
                  .append(",\"confidence\":").append(quote(d.confidence())).append('}');
            }
            sb.append("]}");
        }
        return sb.append(']').toString();
    }

    static String verify(AuditStore.VerifyResult v, ChainAnchorService.AnchorCheck anchors) {
        String status = !v.available() ? "UNAVAILABLE"
                : (v.problems().isEmpty() && anchors.problems().isEmpty()) ? "OK" : "BROKEN";
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"status\":").append(quote(status)).append(',')
          .append("\"checkedRows\":").append(v.checkedRows()).append(',')
          .append("\"anchors\":").append(anchors.anchors()).append(',')
          .append("\"problems\":[");
        int n = 0;
        for (AuditStore.Problem p : v.problems()) {
            if (n++ > 0) sb.append(',');
            sb.append("{\"chainSeq\":").append(p.chainSeq() == null ? "null" : p.chainSeq())
              .append(",\"traceId\":").append(quote(p.traceId()))
              .append(",\"problem\":").append(quote(p.problem())).append('}');
        }
        for (String p : anchors.problems()) {
            if (n++ > 0) sb.append(',');
            sb.append("{\"chainSeq\":null,\"traceId\":null,\"problem\":").append(quote(p)).append('}');
        }
        return sb.append("]}").toString();
    }
}
