package io.hexin.util;

import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;

import io.hexin.bean.User;
import io.hexin.config.Constant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {
	
	@Value("${spring.profiles.active}")
    private String profiles;
	
	/**
	 * 由字符串生成加密key，服务器端定期更新密秘钥
	 * @return
	 */
	public SecretKey generalKey(){
		String stringKey = profiles+Constant.JWT_SECRET;
		byte[] encodedKey = Base64.decodeBase64(stringKey);
	    SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
	    return key;
	}
	
	public static void main(String[] args)throws Exception {
//		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; //签名算法，HMAC using SHA-256
//		System.out.println(signatureAlgorithm.getValue());
//		
//		Header header = new DefaultHeader();
//		JwsHeader jwsHeader = new DefaultJwsHeader(header);
//		jwsHeader.setAlgorithm(signatureAlgorithm.getValue());
//		
//		ObjectMapper OBJECT_MAPPER = new ObjectMapper();
//		try {
//			byte[] writeValueAsBytes = OBJECT_MAPPER.writeValueAsBytes(jwsHeader);
//		} catch (JsonProcessingException e) {
//			e.printStackTrace();
//		}
		User user = new User();
		user.setAccount("Rico Liang");
		user.setPwd("admin888");
		user.setRoleId(1001L);
		user.setUserId(1002L);
		
		String subject = generalSubject(user);
		JwtUtil jwtUtil = new JwtUtil();
		String createJWT = jwtUtil.createJWT("jwt", subject, 60*60*1000L);
		
		Claims parseJWT = jwtUtil.parseJWT(createJWT);
		System.out.println(parseJWT);
	}

	/**
	 * 创建jwt
	 * @param id
	 * @param subject
	 * @param ttlMillis
	 * @return
	 * @throws Exception
	 */
	public String createJWT(String id, String subject, long ttlMillis) throws Exception {
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; //签名算法，HMAC using SHA-256
		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);
		SecretKey key = generalKey(); //算法所对应的秘钥，就好比不同的锁需要相应的钥匙才能打开；如果没有设置秘钥或者秘钥为空，则JWT的第三部分（签名部分）为空
		JwtBuilder builder = Jwts.builder()
			.setId(id) //设置jti：playload部分，jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
			.setIssuedAt(now) //设置iat(issued at)：在什么时候签发的，即jwt的签发时间。
			.setSubject(subject) //设置sub：该JWT所面向的用户
		    .signWith(signatureAlgorithm, key).setHeaderParam("type", Header.JWT_TYPE);//.compressWith(new GzipCompressionCodec()); //设置签名；该方法适用于HMAC签名，如果是RSA或Elliptic Curve签名，则调用signWith(SignatureAlgorithm, Key)方法
		if (ttlMillis >= 0) {
		    long expMillis = nowMillis + ttlMillis;
		    Date exp = new Date(expMillis);
		    builder.setExpiration(exp); //从当前时间往后推多长时间，就是过期时间
		}
		return builder.compact(); //创建一个Jwt Token字符串
	}
	
	/**
	 * 解密jwt
	 * @param jwt
	 * @return
	 * @throws Exception
	 */
	public Claims parseJWT(String jwt) throws Exception{
		SecretKey key = generalKey();
		Claims claims = Jwts.parser()         
		   .setSigningKey(key)
		   .parseClaimsJws(jwt).getBody();
		return claims;
	}
	
	/**
	 * 生成subject信息
	 * @param user
	 * @return
	 */
	public static String generalSubject(User user){
		JSONObject jo = new JSONObject();
		jo.put("userId", user.getUserId());
		jo.put("roleId", user.getRoleId());
		return jo.toJSONString();
	}
}
