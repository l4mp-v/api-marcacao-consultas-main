package com.fiap.eca.api_marcacao_consultas.controller;

import com.fiap.eca.api_marcacao_consultas.model.Usuario;
import com.fiap.eca.api_marcacao_consultas.service.UsuarioService;
import com.fiap.eca.api_marcacao_consultas.security.JwtTokenProvider;
import com.fiap.eca.api_marcacao_consultas.dto.LoginRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {
    private final UsuarioService usuarioService;
    private final JwtTokenProvider jwtTokenProvider;

    public UsuarioController(UsuarioService usuarioService, JwtTokenProvider jwtTokenProvider) {
        this.usuarioService = usuarioService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @GetMapping
    public ResponseEntity<List<Usuario>> listarUsuarios() {
        List<Usuario> usuarios = usuarioService.listarUsuarios();
        return ResponseEntity.ok(usuarios);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> buscarUsuarioPorId(@PathVariable Long id) {
        Optional<Usuario> usuario = usuarioService.buscarUsuarioPorId(id);
        return usuario.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/medicos")
    public ResponseEntity<List<Usuario>> listarMedicos(
            @RequestParam(required = false) String especialidade) {
        List<Usuario> medicos;
        if (especialidade != null && !especialidade.isEmpty()) {
            medicos = usuarioService.buscarMedicosPorEspecialidade(especialidade);
        } else {
            medicos = usuarioService.listarMedicos();
        }
        return ResponseEntity.ok(medicos);
    }

    @PostMapping
    public ResponseEntity<?> criarUsuario(@RequestBody Usuario usuario) {
        try {
            Usuario novoUsuario = usuarioService.salvarUsuario(usuario);
            return ResponseEntity.ok(novoUsuario);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> atualizarUsuario(@PathVariable Long id, @RequestBody Usuario usuario) {
        try {
            Usuario usuarioAtualizado = usuarioService.atualizarUsuario(id, usuario);
            return ResponseEntity.ok(usuarioAtualizado);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> excluirUsuario(@PathVariable Long id) {
        try {
            usuarioService.excluirUsuario(id);
            return ResponseEntity.noContent().build();
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

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

    // ⚠️ ENDPOINT TEMPORÁRIO APENAS PARA TESTES - REMOVER EM PRODUÇÃO
    @PostMapping("/reset-senhas-teste")
    public ResponseEntity<?> resetarSenhasParaTeste() {
        try {
            String senhasTeste = usuarioService.resetarSenhasParaTeste();
            return ResponseEntity.ok().body(Map.of("message", senhasTeste));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    // Endpoint para admin alterar senha de qualquer usuário
    @PutMapping("/{id}/senha")
    public ResponseEntity<?> alterarSenhaUsuario(@PathVariable Long id, @RequestBody Map<String, String> request) {
        try {
            String novaSenha = request.get("novaSenha");
            if (novaSenha == null || novaSenha.trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Nova senha é obrigatória");
            }

            Usuario usuario = usuarioService.alterarSenha(id, novaSenha);
            return ResponseEntity.ok()
                    .body(Map.of("message", "Senha alterada com sucesso", "usuario", usuario.getNome()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
}
