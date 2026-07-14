package com.example.Authentication_XetaX.AuthUser;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/auth/api/v1/users")
@AllArgsConstructor
@NoArgsConstructor
public class AuthUserController {

    @Autowired
    AuthUserService userService;

    @PostMapping("/")
    public ResponseEntity<AuthUserDto> createUser(@RequestBody AuthUserDto userDto) {
        System.out.println("userDto: " + userDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(userDto));
    }



    @GetMapping("/getAllUsers")
    public ResponseEntity<Iterable<AuthUserDto>> getAllUsers() {
        return ResponseEntity.status(HttpStatus.OK).body(userService.getAllUser());
    }

    @GetMapping("/getUserByEmail/{email}")
    public ResponseEntity<AuthUserDto> getUserByEmail(@PathVariable String email) {
        return ResponseEntity.ok(userService.getUserByEmail(email));

    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable String userId) {
        userService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{userId}")
    public ResponseEntity<AuthUserDto> updateUser(
            @RequestBody AuthUserDto userDto,
            @PathVariable String userId) {
        return ResponseEntity.ok(userService.updateUser(userDto, userId));
    }
    @GetMapping("/getUserById/{userId}")
    public ResponseEntity<AuthUserDto>getUserById(@PathVariable ("userId")String userId){
        return ResponseEntity.ok(userService.getUserById(userId));

    }

}
