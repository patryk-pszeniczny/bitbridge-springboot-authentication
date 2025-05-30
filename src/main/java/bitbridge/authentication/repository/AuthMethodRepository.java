package bitbridge.authentication.repository;

import bitbridge.authentication.model.AuthMethod;
import bitbridge.authentication.model.AuthProviderEnum;
import bitbridge.authentication.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthMethodRepository extends JpaRepository<AuthMethod, String> {
    @Query("SELECT a.user FROM AuthMethod a WHERE a.provider = :provider AND a.providerId = :providerId")
    Optional<User> findUserByProviderAndProviderId(
            @Param("provider") AuthProviderEnum provider,
            @Param("providerId") String providerId
    );
    Optional<AuthMethod> findByProviderAndProviderId(AuthProviderEnum provider, String providerId);
}
