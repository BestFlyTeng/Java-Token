import com.alibaba.fastjson.JSONObject;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class TokenUtils {
  // token的签名
  private static final String SIGN = "sign";
  private static final String ENCRYPTION = "HS256";
  // 生成token,参数可以根据需求改
  public static String getToken(Integer id, String email) throws Exception {
    JSONObject headJson = new JSONObject();
    JSONObject payloadJson = new JSONObject();
    headJson.put("typ", "JWT");
    headJson.put("alg", ENCRYPTION);
    payloadJson.put("id", id);
    payloadJson.put("email", email);
    String head = Base64.getEncoder().encodeToString(headJson.toString().getBytes());
    String payload = Base64.getEncoder().encodeToString(payloadJson.toString().getBytes());
    String message = head + payload;
    return key, head + "." + payload + "." + encodeHS256(message);
  }
  // 验证token
  public static boolean parseToken(String token) throws Exception {
    try {
      String[] parts = token.split("\\.");
      if (parts.length != 3) {
        return false;
      }
      String headBase64 = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
      String payloadBase64 = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
      JSONObject headJson = JSONObject.parseObject(headBase64);
      if (!ENCRYPTION.equals(headJson.get("alg")) || !"JWT".equals(headJson.get("typ"))) {
        return false;
      }
      if (!encodeHS256(Base64.getEncoder().encodeToString(headBase64.getBytes()) + Base64.getEncoder().encodeToString(payloadBase64.getBytes())).equals(parts[2])) {
        return false;
      }
    } catch (Exception e) {
      return false;
    }
    return true;
  }

  private static String encodeHS256(String message) throws Exception {
    Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
    SecretKeySpec secretKeySpec = new SecretKeySpec(SIGN.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    hmacSHA256.init(secretKeySpec);
    return Base64.getEncoder().encodeToString(hmacSHA256.doFinal(message.getBytes(StandardCharsets.UTF_8)));
  }
}
