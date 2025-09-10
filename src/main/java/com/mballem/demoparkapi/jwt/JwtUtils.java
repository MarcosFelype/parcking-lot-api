package com.mballem.demoparkapi.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class JwtUtils {
    //JWT CONFIG
    public static final String JWT_BEARER = "Bearer";
    public static final String JWT_AUTHORIZATION = "Authorization";
    public static final String SECRET_KEY = "0123456789-0123456789-0123456789";

    //JWT EXPIRATION
    public static final long EXPIRATION_DAYS = 0;
    public static final long EXPIRATION_HOURS = 0;
    public static final long EXPIRATION_MINUTES = 2;

    private JwtUtils(){

    }

    //chave criptografada para token
    private static Key generateKey(){
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    //expiração do token
    private static Date toExpireDate(Date start){
        LocalDateTime inicio = start.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        LocalDateTime fim = inicio.plusDays(EXPIRATION_DAYS).plusHours(EXPIRATION_HOURS).plusMinutes(EXPIRATION_MINUTES);
        return Date.from(fim.atZone(ZoneId.systemDefault()).toInstant());
    }

    public static JwtToken createToken(String id, String role){
        Date issuedAt = new Date();
        Date limit = toExpireDate(issuedAt);

        String token = Jwts.builder()
                .setHeaderParam("typ", "HWT")
                .setSubject(id)
                .setIssuedAt(issuedAt)
                .setExpirationDate(limit)
                .signWith(generateKey(), SignatureAlgorithm.HS256) //gera a chave do token (a partir do método
        // + assinatura da chave

                .claim("role", role)
                .compact();

        return new JwtToken(token);

    }

    //recuoperar conteúdo do token
    //retorna o corpo do token
    private static Claims getClaimsFromToken(String token){
        try{
            return Jwts.parseBuilder()
                    .setSigninKey(generatedKey()).build()
                    .parseClaimsJws(refractorToken(token).getBody();
        } catch (JwtException ex){
            System.out.println(String.format("Token Invalido %s"), ex.getMessage());
        }
    }

    //retorna um usuário a partir de um token (campo subject)
    public static String getUsernameFromToken(String token){
        return getClaimsFromToken(token).getSubject();
    }

    //retorna se o token é válido (se tem um usuário para o subject passado)
    public static boolean isTokenValid(String token){
        try{
            Jwts.parsedBuilder()
                    .setSigninKey(generatedKey()).build()
                    .parseClaimsJws(refractorToken(token));
        } catch (JwtException ex){
            System.out.println("Token invalido");
            return false;
        }
    }

    //remover do token a expressão Bearer
    private static String refractorToken(String token){
        if (token.contains(JWT_BEARER)){
            return token.substring(JWT_BEARER.length()); //retorna o token sem o bearer. Caracteres a partir do bearer
        }
    }

}

