package ru.kata.spring.boot_security.demo.model;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;

import lombok.Data;

@Entity
@Data
@Table(name = "roles")
public class Role implements GrantedAuthority {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name")
    private String name;

    @Override
    public String getAuthority() {
        return name;
    }
}

