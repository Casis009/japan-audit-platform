package com.audit.rule.detector;

import com.audit.rule.corporate.CorporateNumberValidator;
import com.audit.rule.masking.AuditMaskingService;
import com.audit.rule.model.DetectedItem;
import com.audit.rule.model.DetectedItem.Confidence;
import com.audit.rule.model.DetectionResult;
import com.audit.rule.model.PiiType;
import com.audit.rule.mynumber.MyNumberModulus11Validator;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 日本の個人情報（PII）検知・マスキングエンジン。
 *
 * <h2>検知の3段構え</h2>
 * <ol>
 *   <li><b>ファストパス</b>：数字も「@」も含まないテキストは正規表現を回さずに即返却する。</li>
 *   <li><b>正規表現で候補抽出</b>：前後が数字・ハイフンでない12桁/13桁などを候補にする。</li>
 *   <li><b>チェックディジット検証＋文脈判定</b>：マイナンバー（モジュラス11）・法人番号（モジュラス9）を検証し、
 *       直前に「マイナンバー」「myNumber」等があれば確度 HIGH、なければ MEDIUM とする。</li>
 * </ol>
 *
 * <h2>限界（README・設計書にも明記）</h2>
 * <ul>
 *   <li>モジュラス11を通る12桁は、ランダムな数字でも約1/10ある（検証済み：約10%）。
 *       そのため「誤検知ゼロ」ではなく「誤検知を約1/10に減らす」仕組みである。
 *       マスキングは安全側に倒して MEDIUM も含めて行う。</li>
 *   <li>氏名・住所は形式で判定できないため検知しない。監査DBに本文を保存しない設計（データ最小化）で補う。</li>
 * </ul>
 */
public class JapanPiiDetector {

    /** 12桁（4-4-4のハイフン任意）。前後が数字・ハイフンの場合は長い番号の一部なので除外。 */
    private static final Pattern MY_NUMBER_CANDIDATE =
            Pattern.compile("(?<![\\d-])(\\d{4}-?\\d{4}-?\\d{4})(?![\\d-])");

    /** 13桁（法人番号）。 */
    private static final Pattern CORPORATE_NUMBER_CANDIDATE =
            Pattern.compile("(?<![\\d-])(\\d-?\\d{4}-?\\d{4}-?\\d{4})(?![\\d-])");

    /** 基礎年金番号（4桁-6桁）。チェックディジットがないため形式一致のみ。 */
    private static final Pattern PENSION =
            Pattern.compile("(?<![\\d-])(\\d{4}-\\d{6})(?![\\d-])");

    /** 国内電話番号（携帯 070/080/090、固定電話）。 */
    private static final Pattern PHONE =
            Pattern.compile("(?<![\\d-])(0[789]0-?\\d{4}-?\\d{4}|0\\d{1,4}-\\d{1,4}-\\d{4})(?![\\d-])");

    /** メールアドレス。 */
    private static final Pattern EMAIL =
            Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");

    /** 文脈判定で見る直前の文字数。 */
    private static final int CONTEXT_WINDOW = 40;

    /** マイナンバーの文脈キーワード（小文字・記号除去後に比較）。 */
    private static final List<String> MY_NUMBER_KEYWORDS = List.of(
            "mynumber", "mynum", "kojinbango", "individualnumber", "個人番号", "マイナンバー");

    public DetectionResult scanAndMask(String text) {
        if (text == null || text.isEmpty() || !mayContainPii(text)) {
            return DetectionResult.empty(text);
        }

        List<DetectedItem> found = new ArrayList<>();

        // 1. マイナンバー（モジュラス11）
        Matcher m = MY_NUMBER_CANDIDATE.matcher(text);
        while (m.find()) {
            String candidate = m.group(1);
            if (MyNumberModulus11Validator.isValid(candidate)) {
                Confidence c = hasKeywordBefore(text, m.start(), MY_NUMBER_KEYWORDS) ? Confidence.HIGH : Confidence.MEDIUM;
                found.add(item(PiiType.MY_NUMBER, candidate, m.start(), m.end(), c));
            }
        }

        // 2. 法人番号（モジュラス9）
        m = CORPORATE_NUMBER_CANDIDATE.matcher(text);
        while (m.find()) {
            String candidate = m.group(1);
            if (CorporateNumberValidator.isValid(candidate)) {
                found.add(item(PiiType.CORPORATE_NUMBER, candidate, m.start(), m.end(), Confidence.MEDIUM));
            }
        }

        // 3〜5. 形式のみで判定する項目
        collect(PENSION, PiiType.PENSION_NUMBER, text, found);
        collect(PHONE, PiiType.PHONE_JP, text, found);
        collect(EMAIL, PiiType.EMAIL, text, found);

        if (found.isEmpty()) {
            return DetectionResult.empty(text);
        }

        // 開始位置順に並べ、重なった区間は先に登録した種別（＝優先度が高い種別）を残す
        found.sort(Comparator.comparingInt(DetectedItem::startIndex)); // 安定ソート

        StringBuilder masked = new StringBuilder(text.length());
        List<DetectedItem> kept = new ArrayList<>();
        int last = 0;
        for (DetectedItem it : found) {
            if (it.startIndex() < last) {
                continue; // 重複区間
            }
            masked.append(text, last, it.startIndex()).append(it.maskedValue());
            last = it.endIndex();
            kept.add(it);
        }
        masked.append(text, last, text.length());

        return new DetectionResult(kept, masked.toString());
    }

    /** 数字も「@」もなければ、対象の個人情報は1つも含まれない。 */
    static boolean mayContainPii(String text) {
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if ((ch >= '0' && ch <= '9') || ch == '@') {
                return true;
            }
        }
        return false;
    }

    private static boolean hasKeywordBefore(String text, int start, List<String> keywords) {
        int from = Math.max(0, start - CONTEXT_WINDOW);
        String window = text.substring(from, start)
                .toLowerCase(Locale.ROOT)
                .replaceAll("[\\s_\\-\"':=：]", "");
        return keywords.stream().anyMatch(window::contains);
    }

    private static void collect(Pattern p, PiiType type, String text, List<DetectedItem> out) {
        Matcher m = p.matcher(text);
        while (m.find()) {
            String v = m.groupCount() >= 1 ? m.group(1) : m.group();
            out.add(item(type, v, m.start(), m.end(), Confidence.MEDIUM));
        }
    }

    private static DetectedItem item(PiiType type, String raw, int start, int end, Confidence c) {
        return new DetectedItem(type, raw, AuditMaskingService.mask(type, raw), start, end, c);
    }
}
