package com.audit.collector.json;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MiniJsonTest {

    @Test
    @DisplayName("入れ子・配列・数値・真偽値・null を解析できる")
    void parsesNestedStructures() {
        Map<String, Object> m = MiniJson.parseObject("{\"a\":[1,2.5,{\"b\":true}],\"c\":null,\"d\":-3e2}");
        List<?> a = (List<?>) m.get("a");
        assertEquals(new BigDecimal("1"), a.get(0));
        assertEquals(new BigDecimal("2.5"), a.get(1));
        assertEquals(Boolean.TRUE, ((Map<?, ?>) a.get(2)).get("b"));
        assertNull(m.get("c"));
        assertEquals(0, new BigDecimal("-300").compareTo((BigDecimal) m.get("d")));
    }

    @Test
    @DisplayName("【回帰】値の中のエスケープされた引用符・Unicode を正しく扱う")
    void handlesEscapes() {
        Map<String, Object> m = MiniJson.parseObject("{\"u\":\"/a\\\"b\\\\c\\u3042\\n\"}");
        assertEquals("/a\"b\\cあ\n", m.get("u"));
    }

    @Test
    @DisplayName("不正な JSON・末尾のゴミ・深すぎる入れ子は拒否")
    void rejectsInvalidInput() {
        assertThrows(MiniJson.JsonException.class, () -> MiniJson.parse("{\"a\":1"));
        assertThrows(MiniJson.JsonException.class, () -> MiniJson.parse("{\"a\":1} x"));
        assertThrows(MiniJson.JsonException.class, () -> MiniJson.parse("{a:1}"));
        assertThrows(MiniJson.JsonException.class, () -> MiniJson.parse("[".repeat(100) + "]".repeat(100)));
    }

    @Test
    @DisplayName("quote は < > & もエスケープする（HTML に埋め込まれても安全）")
    void quoteEscapesHtmlChars() {
        String q = MiniJson.quote("<img src=x onerror=alert(1)>");
        assertTrue(!q.contains("<") && !q.contains(">"), q);
        assertEquals("<img src=x onerror=alert(1)>", MiniJson.parse(q));
    }
}
