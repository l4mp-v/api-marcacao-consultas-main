package com.fiap.ecb.api_marcacao_consultas.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String email;
    private String senha;
}