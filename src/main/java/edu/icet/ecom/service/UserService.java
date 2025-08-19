package edu.icet.ecom.service;

import edu.icet.ecom.dto.UserDTO;

import java.util.List;

public interface UserService {
    void createUser(UserDTO userDTO);

    UserDTO getUserById(Long id);

    void updateUser(Long id, UserDTO userDTO);

    void deleteUser(Long id);

    List<UserDTO> getAllUsers();

    UserDTO getUserByEmail(String email);

    String validateUser(UserDTO userDTO);

    void authenticateUser(String email, String password);

    void forgotPassword(String password, String confirmPassword, String newPassword);

    String verify(UserDTO users);
}
