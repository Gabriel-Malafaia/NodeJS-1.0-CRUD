import { compare, hash } from "bcryptjs";
import "dotenv/config";
import express from "express";
import jwt from "jsonwebtoken";
import { v4 as uuid } from "uuid";
import users from "./database";
// Pré configs

const app = express();
app.use(express.json());

const port = 3000;

// Services

const createUserService = async (body) => {
  const { name, email, password, isAdm } = body;
  const keyRequired = ["name", "email", "password", "isAdm"];
  const keyRequest = Object.keys(body);

  const haveAllKeys = keyRequired.every((elem) =>
    keyRequest.some((exist) => exist == elem)
  );

  if (!haveAllKeys) {
    return [
      400,
      {
        status: "error",
        message:
          "The create user must contains: name, email, password and isAdm",
      },
    ];
  }

  const hashPassword = await hash(password, 10);

  const newUser = {
    uuid: uuid(),
    name,
    email,
    password: hashPassword,
    isAdm,
    createdOn: new Date(),
    updatedOn: new Date(),
  };

  users.push(newUser);

  const newUserResponse = { ...newUser };
  delete newUserResponse.password;

  return [201, newUserResponse];
};

const listUsersService = () => {
  return [200, users];
};

const loginUserService = async (body, user) => {
  const { email, password } = body;

  const isValidPassword = await compare(password, user.password);

  if (!isValidPassword) {
    return [401, { message: "Wrong email/password" }];
  }

  const token = jwt.sign({ email }, "SECRET_KEY", {
    expiresIn: "24h",
    subject: user.uuid,
  });

  return [200, { token }];
};

const getUserService = (user) => {
  const userWithNoHash = { ...user };
  delete userWithNoHash.password;

  return [200, userWithNoHash];
};

const updateUserService = async (body, user, entryUuid) => {
  const { password } = body;
  const entryBody = Object.entries(body);
  const updateUser = { ...user };
  const acceptKeys = ["name", "email", "password"];
  updateUser.updatedOn = new Date();

  if (!user.isAdm && entryUuid !== user.uuid) {
    return [403, { message: "Missing authorization headers" }];
  }

  entryBody.forEach((elem) => {
    const key = elem[0];
    const value = elem[1];
    const isAcceptKey = acceptKeys.some((acceptKey) => acceptKey === key);

    if (value && isAcceptKey) {
      updateUser[key] = value;
    }
  });

  if (password) {
    updateUser.password = await hash(password, 10);
  }

  const userIndex = users.findIndex(({ uuid }) => uuid === entryUuid);
  users[userIndex] = updateUser;

  const updateUserPublic = { ...updateUser };
  delete updateUserPublic.password;
  return [200, updateUserPublic];
};

const deleteUserService = (isAdmin, uuidUser) => {
  if (!isAdmin) {
    return [403, { message: "Missing admin permissions" }];
  }

  const userIndex = users.findIndex(({ uuid: uuidDB }) => uuidUser === uuidDB);

  users.splice(userIndex, 1);
  return [204];
};

// Middlewares

const isEmailRegisteredMiddleware = (req, res, next) => {
  const { email } = req.body;

  const emailExists = users.find(({ email: emailDb }) => emailDb === email);

  if (emailExists) {
    return res
      .status(409)
      .json({ status: "error", message: "E-mail already registered" });
  }

  next();
};

const isUserExistMiddleware = (req, res, next) => {
  const { email } = req.body;
  const userExist = users.find(({ email: emailDb }) => email === emailDb);

  if (!userExist) {
    return res.status(401).json({
      message: "Wrong email/password",
    });
  }

  req.user = userExist;
  next();
};

const isTokenValidMiddleware = (req, res, next) => {
  const authToken = req.headers.authorization;
  const actualRoute = req.route.path;

  if (!authToken) {
    return res.status(401).json({ message: "Missing authorization headers" });
  }

  const token = authToken.split(" ")[1];

  try {
    jwt.verify(token, "SECRET_KEY");
  } catch (error) {
    return res.status(403).json({ message: "Missing authorization headers" });
  }

  const userUuid = jwt.decode(token).sub;
  const userInData = users.find(({ uuid }) => uuid === userUuid);

  if (!userInData) {
    return res.status(403).json({ message: "Missing admin permissions" });
  }

  if (actualRoute == "/users" && !userInData.isAdm) {
    return res.status(403).json({ message: "Missing admin permissions" });
  }

  req.user = userInData;

  next();
};

// Controllers

const createUserController = async (req, res) => {
  const body = req.body

  const [status, data] = await createUserService(body);
  return res.status(status).json(data);
};

const listUsersController = (req, res) => {
  const [status, data] = listUsersService();
  return res.status(status).json(data);
};

const loginUserController = async (req, res) => {
  const body = req.body;
  const user = req.user;

  const [status, data] = await loginUserService(body, user);
  return res.status(status).json(data);
};

const getUserController = (req, res) => {
  const user = req.user;

  const [status, data] = getUserService(user);
  return res.status(status).json(data);
};

const updateUserController = async (req, res) => {
  const body = req.body;
  const user = req.user;
  const uuid = req.params.uuid;

  const [status, data] = await updateUserService(body, user, uuid);
  return res.status(status).json(data);
};

const deleteUserController = (req, res) => {
  const { isAdm } = req.user;
  const { uuid } = req.params;

  const [status, data] = deleteUserService(req);
  return res.status(status).json(data);
};

// Users routes

app.post("/users", isEmailRegisteredMiddleware, createUserController);
app.get("/users", isTokenValidMiddleware, listUsersController);
app.get("/users/profile", isTokenValidMiddleware, getUserController);
app.patch("/users/:uuid", isTokenValidMiddleware, updateUserController);
app.delete("/users/:uuid", isTokenValidMiddleware, deleteUserController);

// Login routes

app.post("/login", isUserExistMiddleware, loginUserController);

app.listen(port, () => {
  console.log(`Server is running in http://localhost:${port}/`);
});

export default app;
