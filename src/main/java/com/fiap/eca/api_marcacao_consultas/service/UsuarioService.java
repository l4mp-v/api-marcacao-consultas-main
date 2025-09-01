package com.fiap.eca.api_marcacao_consultas.service;

import com.fiap.eca.api_marcacao_consultas.model.Usuario;
import com.fiap.eca.api_marcacao_consultas.repository.UsuarioRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class UsuarioService {
    private final UsuarioRepository usuarioRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    public List<Usuario> listarUsuarios() {
        return usuarioRepository.findAll();
    }

    public Optional<Usuario> buscarUsuarioPorId(Long id) {
        return usuarioRepository.findById(id);
    }

    public List<Usuario> listarMedicos() {
        return usuarioRepository.findByTipo("MEDICO");
    }

    public List<Usuario> buscarMedicosPorEspecialidade(String especialidade) {
        return usuarioRepository.findByTipoAndEspecialidade("MEDICO", especialidade);
    }

    public Usuario salvarUsuario(Usuario usuario) {
        // Verifica se o e-mail já está cadastrado
        Optional<Usuario> usuarioExistente = usuarioRepository.findByEmail(usuario.getEmail());
        if (usuarioExistente.isPresent()) {
            throw new RuntimeException("Erro: Este e-mail já está cadastrado.");
        }

        // Criptografa a senha antes de salvar
        usuario.setSenha(passwordEncoder.encode(usuario.getSenha()));
        return usuarioRepository.save(usuario);
    }

    public Usuario atualizarUsuario(Long id, Usuario usuario) {
        Usuario usuarioExistente = usuarioRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        // Verifica se o e-mail já está sendo usado por outro usuário
        if (!usuarioExistente.getEmail().equals(usuario.getEmail())) {
            Optional<Usuario> usuarioComMesmoEmail = usuarioRepository.findByEmail(usuario.getEmail());
            if (usuarioComMesmoEmail.isPresent()) {
                throw new RuntimeException("Erro: Este e-mail já está sendo usado por outro usuário.");
            }
        }

        // Atualiza os campos
        usuarioExistente.setNome(usuario.getNome());
        usuarioExistente.setEmail(usuario.getEmail());

        // Atualiza a senha apenas se uma nova senha for fornecida
        if (usuario.getSenha() != null && !usuario.getSenha().isEmpty()) {
            usuarioExistente.setSenha(passwordEncoder.encode(usuario.getSenha()));
        }

        // Atualiza o tipo apenas se for fornecido
        if (usuario.getTipo() != null && !usuario.getTipo().isEmpty()) {
            usuarioExistente.setTipo(usuario.getTipo());
        }

        return usuarioRepository.save(usuarioExistente);
    }

    public void excluirUsuario(Long id) {
        if (!usuarioRepository.existsById(id)) {
            throw new RuntimeException("Usuário não encontrado");
        }
        usuarioRepository.deleteById(id);
    }

    public Usuario autenticar(String email, String senha) {
        Usuario usuario = usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (!passwordEncoder.matches(senha, usuario.getSenha())) {
            throw new RuntimeException("Senha incorreta");
        }

        return usuario;
    }

    public Usuario buscarPorEmail(String email) {
        return usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
    }

    // ⚠️ MÉTODO TEMPORÁRIO APENAS PARA TESTES - REMOVER EM PRODUÇÃO
    public String resetarSenhasParaTeste() {
        List<Usuario> usuarios = usuarioRepository.findAll();
        StringBuilder resultado = new StringBuilder("Senhas resetadas para:\n\n");

        for (Usuario usuario : usuarios) {
            String novaSenha = "123456"; // Senha padrão para todos os usuários em teste
            usuario.setSenha(passwordEncoder.encode(novaSenha));
            usuarioRepository.save(usuario);

            resultado.append(String.format("- %s (%s): senha = %s\n",
                    usuario.getNome(), usuario.getEmail(), novaSenha));
        }

        return resultado.toString();
    }

    // Método para admin alterar senha de qualquer usuário
    public Usuario alterarSenha(Long usuarioId, String novaSenha) {
        Usuario usuario = usuarioRepository.findById(usuarioId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        // Criptografa a nova senha
        String senhaCriptografada = passwordEncoder.encode(novaSenha);
        usuario.setSenha(senhaCriptografada);

        return usuarioRepository.save(usuario);
    }
}
