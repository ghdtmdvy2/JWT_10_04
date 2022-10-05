package com.ll.exam.app__2022_10_04.app.jwt;

import com.ll.exam.app__2022_10_04.util.Util;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtProvider {
    private final SecretKey jwtSecretKey;

    private SecretKey getSecretKey() {
        return jwtSecretKey;
    }

    public String generateAccessToken(Map<String, Object> claims, int seconds) {
        long now = new Date().getTime();
        // 만료 날짜 정의.
        Date accessTokenExpiresIn = new Date(now + 1000L * seconds);

        return Jwts.builder()
                // 데이터를 json 형태로 만들기.
                .claim("body", Util.json.toStr(claims))
                // 만료 날짜 설정.
                .setExpiration(accessTokenExpiresIn)
                // SecretKey 로 JWT 비번 걸고, HS512 로 암호화
                .signWith(getSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public boolean verify(String token) {
        try {
            Jwts.parserBuilder()
                    // SecretKey 로 변조 되었는지 확인.
                    .setSigningKey(getSecretKey())
                    .build()
                    .parseClaimsJws(token);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public Map<String, Object> getClaims(String token) {
        String body = Jwts.parserBuilder()
                // SecretKey 로 변조 되었는지 확인.
                .setSigningKey(getSecretKey())
                .build()
                // accessToken (JWT 토큰) 으로 claims(메인 데이터) 가져오기.
                .parseClaimsJws(token)
                .getBody()
                // 어느 데이터 부분만 가져올지 결정. body는 메인 데이터를 뜻함.
                .get("body", String.class);

        return Util.json.toMap(body);
    }
}