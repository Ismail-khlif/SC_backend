package tn.solarchain.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import tn.solarchain.domain.Authority;

import java.util.Optional;

@Repository
public interface AuthorityRepository extends MongoRepository<Authority, String> {
    Optional<Authority> findByName(String authority);
}