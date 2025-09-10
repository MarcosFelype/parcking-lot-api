package com.mballem.demoparkapi.jwt;

import com.mballem.demoparkapi.entity.Usuario;

//armazena as informações do usuário logado
public class JwtUserDetails extends User { //User do SpringSecurity

     public Usuario usuario;
     public JwtUserDetails(Usuario usuario){ //o "aurhorities" contém uma coleção de perfis de usuário

     }
}
