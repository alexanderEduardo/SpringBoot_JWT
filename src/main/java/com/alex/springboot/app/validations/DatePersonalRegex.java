package com.alex.springboot.app.validations;
import javax.validation.Constraint;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static java.lang.annotation.ElementType.METHOD;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
@Constraint(validatedBy = DatePersonalRegexValid.class)
@Retention(RUNTIME)
@Target({FIELD,METHOD})
public @interface DatePersonalRegex {
    java.lang.String message() default "{Campo Requerido Apellido -Requerido}";

    java.lang.Class<?>[] groups() default {};

    java.lang.Class<? extends javax.validation.Payload>[] payload() default {};
}
