package security.oauth2.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.oauth2.auth.domain.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Boolean existsByToken(String Token);

    void deleteByToken(String Token);
}