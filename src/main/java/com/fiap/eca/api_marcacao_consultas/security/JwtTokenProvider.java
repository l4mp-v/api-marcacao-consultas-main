package com.fiap.eca.api_marcacao_consultas.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {
    private final Key chaveSecreta;

    @Value("${jwt.expiration}")
    private long tempoExpiracao;

    public JwtTokenProvider(@Value("${jwt.secret}") String segredo) {
        // Usar a chave secreta configurada no application.properties
        // Isso garante que a chave seja consistente entre reinicializações
        byte[] keyBytes = segredo.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        this.chaveSecreta = Keys.hmacShaKeyFor(keyBytes);
    }

    // Gerar token JWT
    public String gerarToken(String email) {
        Date agora = new Date();
        Date expiracao = new Date(agora.getTime() + tempoExpiracao);

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(agora)
                .setExpiration(expiracao)
                .signWith(chaveSecreta, SignatureAlgorithm.HS256)
                .compact();
    }

    // Extrair email do token
    public String obterEmailDoToken(String token) {
        return Jwts.parser()
                .verifyWith((javax.crypto.SecretKey) chaveSecreta)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    // Validar token JWT
    public boolean validarToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith((javax.crypto.SecretKey) chaveSecreta)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}