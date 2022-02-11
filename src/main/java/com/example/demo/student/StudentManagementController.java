package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(                /*Adding Students using Simple ArrayList*/
            new Student(1, "James"),
            new Student(2, "Erik"),
            new Student(3, "Mariam")
    );

    /*TO PUT ON @PreAuthorize -> hasRole('ROLE_'), hasAnyRole('ROLE_'), hasAuthority('permission'), hasAnyAuthority('permission')*/

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")              /*PERMISSIONS Method #2 Using @PreAuthorize()*/
    public List<Student> getAllStudents(){
        System.out.println("getAllStudents()");
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('student:write')")                           /*PERMISSIONS Method #2 Using @PreAuthorize()*/
    public void registerNewStudent(@RequestBody Student student){
        System.out.println("registerNewStudent()");
        System.out.println("student = " + student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAnyAuthority('student:write')")                           /*PERMISSIONS Method #2 Using @PreAuthorize()*/
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println("deleteStudent()");
        System.out.println("studentId = " + studentId);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAnyAuthority('student:write')")                           /*PERMISSIONS Method #2 Using @PreAuthorize()*/
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        System.out.println("updateStudent()");
        System.out.println(String.format("%s %s",studentId, student));
    }


}
