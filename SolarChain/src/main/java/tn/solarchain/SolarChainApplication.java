package tn.solarchain;

import io.mongock.runner.springboot.EnableMongock;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
@EnableMongock
public class SolarChainApplication {

    public static void main(String[] args) {
        SpringApplication.run(SolarChainApplication.class, args);
    }


}