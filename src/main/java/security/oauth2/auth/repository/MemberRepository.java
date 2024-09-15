package security.oauth2.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.oauth2.auth.domain.Member;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByUsername(String username);

    Optional<Member> findByEmail(String email);
}
