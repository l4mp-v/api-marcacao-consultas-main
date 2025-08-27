package com.fiap.eca.api_marcacao_consultas.controller;

import com.fiap.eca.api_marcacao_consultas.model.Usuario;
import com.fiap.eca.api_marcacao_consultas.service.UsuarioService;
import com.fiap.eca.api_marcacao_consultas.security.JwtTokenProvider;
import com.fiap.eca.api_marcacao_consultas.dto.LoginRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {
    private final UsuarioService usuarioService;
    private final JwtTokenProvider jwtTokenProvider;

    // ... outros endpoints

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            Usuario usuario = usuarioService.autenticar(loginRequest.getEmail(), loginRequest.getSenha());
            String token = jwtTokenProvider.gerarToken(usuario.getEmail());
            return ResponseEntity.ok().body(Map.of("token", token));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas");
        }
    }

    // NOVO: Endpoint para buscar usuário atual baseado no JWT
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@RequestHeader("Authorization") String authHeader) {
        try {
            // Remove "Bearer " do header
            String token = authHeader.substring(7);

            // Extrai o email do token
            String email = jwtTokenProvider.obterEmailDoToken(token);

            // Busca o usuário pelo email
            Usuario usuario = usuarioService.buscarPorEmail(email);

            return ResponseEntity.ok(usuario);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token inválido");
        }
    }
}

    // ===== ADIÇÃO PARA CONECTAR FRONT E BACK =====
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuário não autenticado");
        }
        String email = authentication.getName();
        return ResponseEntity.ok(Map.of(
                "id", 0,            // ajuste se quiser buscar no banco
                "nome", email,      // ajuste para retornar nome real
                "email", email,
                "tipo", "PACIENTE"  // ajuste conforme seu modelo (ADMIN/MEDICO/PACIENTE)
        ));
    }
}