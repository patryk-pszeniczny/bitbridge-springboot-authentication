package bitbridge.authentication.domain.repository;

import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.domain.model.UserAuthMethod;
import bitbridge.authentication.domain.valueobject.AuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserAuthMethodRepository extends JpaRepository<UserAuthMethod, UUID> {
    @Query("SELECT a.user FROM UserAuthMethod a WHERE a.provider = :provider AND a.providerId = :providerId")
    Optional<User> findUserByProviderAndProviderId(
            @Param("provider") AuthProvider provider,
            @Param("providerId") String providerId
    );
    Optional<UserAuthMethod> findByProviderAndProviderId(AuthProvider provider, String providerId);
}
