package edu.icet.ecom.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface JWTService {
    String generateToken(String username);
    String extractUsername(String token);
    boolean validateToken(String jwtToken, UserDetails userDetails);

}
