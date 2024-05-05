import { bcryptAdapter, envs, JwtAdapter } from '../../config';
import { EmailService } from './email.service';
import { UserModel } from '../../data';
import { CustomError, LoginUserDto, RegisterUserDto } from '../../domain';
import { UserEntity } from '../../domain/entitis/user.entity';


export class AuthService {
    constructor(
        private readonly emailService: EmailService,
    ){}

    public async registerUser( registerUserDto: RegisterUserDto ) {

        console.log(registerUserDto)
        
        const existUser = await UserModel.findOne({email: registerUserDto.email})
        if ( existUser ) throw CustomError.badRequest("Email already exist");

        try {
            
            const user = new UserModel(registerUserDto);
            user.password = bcryptAdapter.hash(registerUserDto.password)

            await user.save();

            await this.senderEmailValidationLink( user.email )

            const { password, ...userEntity } = UserEntity.fromObject(user);

            const token = await JwtAdapter.generateToken({id: user.id})

            if (!token) throw CustomError.internalServer("Error while creating JWT")

            return { 
                user: userEntity,
                token: token
            };

        } catch (error) {
            console.log("entro aca")
            throw CustomError.internalServer(`${error}`)
        }
    }

    public async loginUser( loginUserDto: LoginUserDto ) {

        const user = await UserModel.findOne({email: loginUserDto.email})

        if (!user) throw CustomError.badRequest("Email not exist");

        const isMatching = bcryptAdapter.compare( loginUserDto.password , user.password );
        if ( !isMatching ) throw CustomError.badRequest("Password is not valid");

        const { password, ...userEntity } = UserEntity.fromObject(user);

        const token = await JwtAdapter.generateToken({ id: user.id });

        if ( !token ) throw CustomError.internalServer("Error while creating JWT");

        return {
            user: userEntity,
            token: token
        }
        
    }

    private senderEmailValidationLink = async ( email: string ) => {
        const token = await JwtAdapter.generateToken({email})
        if(!token) throw CustomError.internalServer("Error getting token");
        const link = `${ envs.WEBSERVICE_URL }auth/validate-email/${ token }`;
        const html = `
        <h1>Validate your email</h1>

        <p>Click on the following link to validate your email</p>
        <a href="${ link }">Validate your email: ${ email }</a>
        <p>${link}</p>
        `;

        const options = {
            to: email,
            subject: "Validate your email",
            htmlBody: html,
        }

        const isSent = await this.emailService.sendEmail(options);

        if ( !isSent ) throw CustomError.internalServer("Error sending email")

        return true;
    }

    public validateEmail = async (token: string) => {
        const payload = await JwtAdapter.validateToke(token);

        if ( !payload ) throw CustomError.unauthorized("Invalid token");

        const { email } = payload as { email: string };
        if ( !email ) throw CustomError.internalServer("Email not in token");

        const user = await UserModel.findOne({email});
        if ( !user ) throw CustomError.internalServer("Email not exists");

        user.emailValidated = true;

        await user.save();

        return true;
    }
    
}

