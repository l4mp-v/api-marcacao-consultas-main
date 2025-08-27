package com.fiap.eca.api_marcacao_consultas.model;
import jakarta.persistence.*;
import lombok.Data;
@Data
@Entity
@Table(name = "usuarios")
public class Usuario {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String nome;
    private String email;
    private String senha;
    private String tipo; // Paciente, Médico ou Admin
    private String especialidade; // Especialidade do médico (null para pacientes e admin)
}