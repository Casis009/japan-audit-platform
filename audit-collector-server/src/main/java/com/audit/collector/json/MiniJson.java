package com.audit.collector.json;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 依存ライブラリなしの小さな JSON パーサー（RFC 8259 の範囲で厳密に解析）。
 * <p>
 * 旧実装は {@code indexOf("\"key\":\"")} で文字列を切り出しており、
 * 値にエスケープされた引用符があると壊れ、入れ子や数値の型も扱えなかった。
 * <p>
 * 返す型：Object → {@code Map<String,Object>}、配列 → {@code List<Object>}、
 * 文字列 → String、数値 → BigDecimal、真偽値 → Boolean、null → null。
 * 入れ子の深さは {@link #MAX_DEPTH} までに制限（深い入れ子でスタックを溢れさせる攻撃への対策）。
 */
public final class MiniJson {

    public static final int MAX_DEPTH = 32;

    private final String s;
    private int pos;

    private MiniJson(String s) {
        this.s = s;
    }

    public static Object parse(String text) {
        if (text == null) {
            throw new JsonException("input is null", 0);
        }
        MiniJson p = new MiniJson(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.pos != text.length()) {
            throw new JsonException("unexpected trailing characters", p.pos);
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new JsonException("top-level value must be an object", 0);
        }
        return (Map<String, Object>) v;
    }

    private Object value(int depth) {
        if (depth > MAX_DEPTH) {
            throw new JsonException("nesting too deep", pos);
        }
        if (pos >= s.length()) {
            throw new JsonException("unexpected end of input", pos);
        }
        char c = s.charAt(pos);
        return switch (c) {
            case '{' -> object(depth);
            case '[' -> array(depth);
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> {
                if (c == '-' || (c >= '0' && c <= '9')) {
                    yield number();
                }
                throw new JsonException("unexpected character '" + c + "'", pos);
            }
        };
    }

    private Map<String, Object> object(int depth) {
        Map<String, Object> m = new LinkedHashMap<>();
        pos++; // {
        ws();
        if (peek('}')) {
            pos++;
            return m;
        }
        while (true) {
            ws();
            if (!peek('"')) {
                throw new JsonException("object key must be a string", pos);
            }
            String key = string();
            ws();
            expect(':');
            ws();
            m.put(key, value(depth + 1));
            ws();
            if (peek(',')) {
                pos++;
                continue;
            }
            expect('}');
            return m;
        }
    }

    private List<Object> array(int depth) {
        List<Object> list = new ArrayList<>();
        pos++; // [
        ws();
        if (peek(']')) {
            pos++;
            return list;
        }
        while (true) {
            ws();
            list.add(value(depth + 1));
            ws();
            if (peek(',')) {
                pos++;
                continue;
            }
            expect(']');
            return list;
        }
    }

    private String string() {
        pos++; // opening quote
        StringBuilder sb = new StringBuilder();
        while (pos < s.length()) {
            char c = s.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                if (pos >= s.length()) {
                    break;
                }
                char e = s.charAt(pos++);
                switch (e) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > s.length()) {
                            throw new JsonException("bad unicode escape", pos);
                        }
                        try {
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                        } catch (NumberFormatException ex) {
                            throw new JsonException("bad unicode escape", pos);
                        }
                        pos += 4;
                    }
                    default -> throw new JsonException("bad escape \\" + e, pos - 1);
                }
            } else if (c < 0x20) {
                throw new JsonException("control character in string", pos - 1);
            } else {
                sb.append(c);
            }
        }
        throw new JsonException("unterminated string", pos);
    }

    private BigDecimal number() {
        int start = pos;
        if (peek('-')) pos++;
        digits();
        if (peek('.')) {
            pos++;
            digits();
        }
        if (peek('e') || peek('E')) {
            pos++;
            if (peek('+') || peek('-')) pos++;
            digits();
        }
        try {
            return new BigDecimal(s.substring(start, pos));
        } catch (NumberFormatException e) {
            throw new JsonException("bad number", start);
        }
    }

    private void digits() {
        int start = pos;
        while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
        if (pos == start) {
            throw new JsonException("digit expected", pos);
        }
    }

    private Object literal(String word, Object v) {
        if (!s.startsWith(word, pos)) {
            throw new JsonException("unexpected token", pos);
        }
        pos += word.length();
        return v;
    }

    private void ws() {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
            else break;
        }
    }

    private boolean peek(char c) {
        return pos < s.length() && s.charAt(pos) == c;
    }

    private void expect(char c) {
        if (!peek(c)) {
            throw new JsonException("'" + c + "' expected", pos);
        }
        pos++;
    }

    /** JSON 文字列として安全に書き出す（レスポンス生成用）。 */
    public static String quote(String v) {
        if (v == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(v.length() + 2).append('"');
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '<' -> sb.append("\\u003c"); // HTML に埋め込まれても安全なように
                case '>' -> sb.append("\\u003e");
                case '&' -> sb.append("\\u0026");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }

    public static final class JsonException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public JsonException(String msg, int pos) {
            super(msg + " at position " + pos);
        }
    }
}
