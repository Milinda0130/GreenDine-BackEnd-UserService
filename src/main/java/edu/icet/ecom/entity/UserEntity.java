package edu.icet.ecom.entity;

import javax.persistence.*;
import lombok.*;

import java.util.Date;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "user")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String fullname;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    private String phoneNumber;
    private Date dateOfBirth;

    @Column(nullable = false)
    private String password;

    // ⚠️ Normally you should NOT store confirmPassword in DB
    @Transient   // <--- this makes Hibernate ignore it
    private String confirmPassword;
}
