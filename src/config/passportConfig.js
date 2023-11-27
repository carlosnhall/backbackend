import passport from "passport";
import local from "passport-local";
import { UserController } from "../components/sessions/userController.js";
import { CartController } from "../components/carts/cartController.js";
import GitHubStrategy from "passport-github2";
import GoogleStrategy from "passport-google-oauth2";
import jwt from "passport-jwt";
import {
  generateToken,
  extractCookie,
} from "../middlewares/authMiddlewares.js";
import {
  createHash,
  isValidPassword,
} from "../middlewares/passwordMiddlewares.js";
import dotenv from "dotenv";
dotenv.config();

const LocalStrategy = local.Strategy;
const JWTStrategy = jwt.Strategy;
const ExtractJWT = jwt.ExtractJwt;
let cartController = new CartController();
let userController = new UserController();

const initializePassport = () => {
  passport.use(
    "google",
    new GoogleStrategy(
      {
        clientID:
          "247017939371-alft77h3a2gqngsv66q4vuqd20vstl1j.apps.googleusercontent.com",
        clientSecret: "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",
        callbackURL: `${process.env.DOMAIN_NAME}/session/googlecallback`,
        passReqToCallback: true,
      },
      async (req, accessToken, refreshToken, profile, done) => {
        try {
          const user = await userController.searchUser(profile._json.email);
          if (user) {
            user.token = generateToken(user);
            const redirectUrl = `${process.env.FRONT_DOMAIN}/loggedin?token=${user.token}`;
            return done(null, { ...user._doc, token: user.token, redirectUrl });
          }

          const newUser = {
            first_name: profile._json.given_name,
            last_name: profile._json.family_name,
            user: profile._json.given_name,
            social: "google",
            rol: "user",
            email: profile._json.email,
            password: "",
          };
          const result = await userController.createUser(newUser);
          result.token = generateToken(result);
          const redirectUrl = `${process.env.FRONT_DOMAIN}/loggedin?token=${result.token}`;
          return done(null, {
            ...result._doc,
            token: result.token,
            redirectUrl,
          });
        } catch (error) {
          return done("error to login with Google" + error);
        }
      }
    )
  );

  passport.use(
    "github",
    new GitHubStrategy(
      {
        clientID: "Iv1.8aa53fcd01061557",
        clientSecret: "19f48d7e281586b848ad184d08ab28e87bc6c0e8",
        callbackURL: `${process.env.DOMAIN_NAME}/session/githubcallback`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const user = await userController.searchUser(profile._json.email);
          if (user) {
            user.token = generateToken(user);
            const redirectUrl = `${process.env.FRONT_DOMAIN}/loggedin?token=${user.token}`;
            return done(null, { ...user._doc, token: user.token, redirectUrl });
          }

          const newUser = {
            user: profile._json.login,
            first_name: profile._json.name,
            last_name: "",
            rol: "user",
            social: "github",
            email: profile._json.email,
            password: "",
          };

          const result = await userController.createUser(newUser);
          result.token = generateToken(result);
          const redirectUrl = `${process.env.FRONT_DOMAIN}/loggedin?token=${result.token}`;
          return done(null, {
            ...result._doc,
            token: result.token,
            redirectUrl,
          });
        } catch (error) {
          return done("error to login with GitHub" + error);
        }
      }
    )
  );

  passport.use(
    "login",
    new LocalStrategy(
      {
        usernameField: "email",
      },
      async (username, password, done) => {
        try {
          let user = await userController.searchUser(username);
          if (!user) {
            return done(null, false);
          }
          if (!isValidPassword(user, password)) return done(null, false);
          let token = generateToken(user);
          let newUser = { ...user._doc, token: token };
          return done(null, newUser);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
  passport.use(
    "register",
    new LocalStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, username, password, done) => {
        let userNew = req.body;
        try {
          const user = await userController.searchUser(
            username || userNew.email
          );

          if (user) {
            return done(null, false);
          }
          if (
            userNew.email.includes(process.env.ADMIN_EMAIL_INCLUDES) &&
            userNew.password == process.env.ADMIN_PASSWORD_INCLUDES
          ) {
            let asignarRol = {
              ...userNew,
              rol: "admin",
            };
            userNew = asignarRol;
          } else {
            let asignarRol = {
              ...userNew,
              rol: "user",
            };
            userNew = asignarRol;
          }
          const hashUser = {
            ...userNew,
            social: "local",
            password: createHash(userNew.password),
          };
          const result = await userController.createUser(hashUser);
          return done(null, result);
        } catch (error) {
          return done("Error al obtener usuario");
        }
      }
    )
  );

  passport.use(
    "jwt",
    new JWTStrategy(
      {
        jwtFromRequest: ExtractJWT.fromExtractors([extractCookie]),
        secretOrKey: process.env.JWT_PRIVATE_KEY,
      },
      async (jwt_payload, done) => {
        done(null, jwt_payload);
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user._id);
  });
  passport.deserializeUser(async (id, done) => {
    const user = await userController.searchUserById(id);
    done(null, user);
  });
};

export default initializePassport;
