package tn.solarchain.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import tn.solarchain.domain.Authority;


@Repository
public interface AuthorityRepository extends MongoRepository<Authority, String> {}