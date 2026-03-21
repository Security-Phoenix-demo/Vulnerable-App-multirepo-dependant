package org.sasanlabs.dependent.config;

import org.sasanlabs.shared.config.SharedDatabaseConfig;
import org.sasanlabs.shared.config.SharedJWTConfig;
import org.sasanlabs.shared.config.SharedCryptoConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.security.SecureRandom;

/**
 * Service configuration that imports shared config constants.
 * Pattern 4: Consumes hardcoded credentials and weak crypto defaults from shared library.
 */
@Configuration
public class ServiceConfiguration {

    /**
     * VULNERABLE: Uses hardcoded credentials from SharedDatabaseConfig.
     */
    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName(SharedDatabaseConfig.DB_DRIVER);
        ds.setUrl(SharedDatabaseConfig.DB_URL);
        ds.setUsername(SharedDatabaseConfig.ADMIN_USER);
        ds.setPassword(SharedDatabaseConfig.ADMIN_PASSWORD);
        return ds;
    }

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    /**
     * VULNERABLE: Uses predictable SecureRandom from SharedCryptoConfig.
     */
    @Bean
    public SecureRandom secureRandom() {
        return SharedCryptoConfig.getSecureRandom();
    }
}
