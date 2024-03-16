package com.bezkoder.springjwt.security.services;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.bezkoder.springjwt.execption.TokenRefreshException;
import com.bezkoder.springjwt.models.RefreshToken;
import com.bezkoder.springjwt.repository.RefreshTokenRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
public class RefreshTokenService {
    @Value("${bezkoder.app.jwtRefreshExpirationMs}")
    private Long refreshTokenDurationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(Long User_Id) {
        // Check if a refresh token already exists for the user
        Optional<RefreshToken> existingToken = refreshTokenRepository.findByUser_Id(User_Id);
        if (existingToken.isPresent()) {
            // Update the existing refresh token
            RefreshToken refreshToken = existingToken.get();
            refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
            refreshToken.setToken(UUID.randomUUID().toString());
            return refreshTokenRepository.save(refreshToken);
        } else {
            // Create a new refresh token
            RefreshToken newRefreshToken = new RefreshToken();
            newRefreshToken.setUser(userRepository.findById(User_Id).get());
            newRefreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
            newRefreshToken.setToken(UUID.randomUUID().toString());
            return refreshTokenRepository.save(newRefreshToken);
        }
    }


    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }

        return token;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
    }
}