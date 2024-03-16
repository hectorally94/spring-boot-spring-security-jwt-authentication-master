package com.bezkoder.springjwt.payload.response;

import java.util.List;

public class JwtResponse {
  private String token;
  private String type = "Bearer";

  private String refreshToken;
  private Long id;
  private String username;

  private String nomPrenom;

  private String phoneNumber;
  private List<String> roles;

  public JwtResponse(String accessToken,String refreshToken, Long id, String username, String nomPrenom,String phoneNumber, List<String> roles) {
    this.token = accessToken;
    this.refreshToken=refreshToken;
    this.id = id;
    this.username = username;
    this.nomPrenom=nomPrenom;
    this.phoneNumber=phoneNumber;
    this.roles = roles;
  }

  public String getRefreshToken() {
    return refreshToken;
  }

  public void setRefreshToken(String refreshToken) {
    this.refreshToken = refreshToken;
  }

  public String getAccessToken() {
    return token;
  }

  public void setAccessToken(String accessToken) {
    this.token = accessToken;
  }

  public String getTokenType() {
    return type;
  }

  public void setTokenType(String tokenType) {
    this.type = tokenType;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getNomPrenom() {
    return nomPrenom;
  }

  public void setNomPrenom(String nomPrenom) {
    this.nomPrenom = nomPrenom;
  }

  public String getPhoneNumber() {
    return phoneNumber;
  }

  public void setPhoneNumber(String phoneNumber) {
    this.phoneNumber = phoneNumber;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public List<String> getRoles() {
    return roles;
  }
}
