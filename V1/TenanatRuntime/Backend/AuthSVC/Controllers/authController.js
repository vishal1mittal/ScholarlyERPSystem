const { authenticate, authorize } = require("../Services/authService");
const { createError } = require("../../Error/CustomErrorHandler");
const authService = require("../Services/authService");

async function registerUser(req, res, next) {
    authService.registerUser(
        "vishalmittalrohini@gmail.com",
        "MobileA@1",
        "User"
    );
}
async function loginUser(req, res, next) {}
async function enable2FA(req, res, next) {}
async function disable2FA(req, res, next) {}
async function setup2FA(req, res, next) {}
async function verify2FA(req, res, next) {}
async function getMe(req, res, next) {}

module.exports = {
    registerUser,
    loginUser,
    enable2FA,
    disable2FA,
    setup2FA,
    verify2FA,
    getMe,
};
