package com.audit.collector.store;

import com.audit.collector.model.IngestRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * 検知明細のダイジェスト（SHA-256）。
 * <p>
 * DB 側の {@code fn_audit_details_digest()} と<b>完全に同じ式</b>で計算する必要がある：
 * 各明細を「seq_no␟pii_type␟masked_value␟occurred_in␟confidence」（␟ = U+001F）にし、
 * seq_no 順に「␞」（U+001E）でつないだ文字列の SHA-256（16進小文字）。明細0件なら空文字列の SHA-256。
 * この値を本体行に入れてハッシュチェーンに含めることで、明細テーブルの改ざんも検出できる。
 */
public final class DetailDigest {

    private static final char UNIT_SEP = '\u001F';
    private static final char RECORD_SEP = '\u001E';

    private DetailDigest() {
    }

    public static String of(List<IngestRequest.Detail> details) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < details.size(); i++) {
            IngestRequest.Detail d = details.get(i);
            if (i > 0) {
                sb.append(RECORD_SEP);
            }
            sb.append(d.seqNo()).append(UNIT_SEP)
              .append(d.piiType()).append(UNIT_SEP)
              .append(d.maskedValue()).append(UNIT_SEP)
              .append(d.occurredIn()).append(UNIT_SEP)
              .append(d.confidence());
        }
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
