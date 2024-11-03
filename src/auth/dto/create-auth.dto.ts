import { IsEmail, IsString, Matches, MinLength } from "class-validator";

export class CreateAuthDto {
    @IsString()
    username: string;

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    @Matches(/^(?=.*[0-9])/, { message: 'Password must contain at least one number and have a minimum length of 6 characters' })
    password: string;
}
