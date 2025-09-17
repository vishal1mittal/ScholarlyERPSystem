function isValidEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}
function isValidPhone(phone) {
    const regex = /^\+?[1-9]\d{7,14}$/;
    return regex.test(phone);
}
function isValidPassword(password) {
    // At least 8 chars, one uppercase, one lowercase, one digit, one special char
    const regex =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return regex.test(password);
}
function isValidUUID(uuid) {
    const regex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return regex.test(uuid);
}
function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}
function isValidISODate(date) {
    const regex = /^\d{4}-\d{2}-\d{2}$/;
    if (!regex.test(date)) return false;

    const parsedDate = new Date(date);
    return !isNaN(parsedDate.getTime());
}

function isValidOTP(otp, length = 6) {
    const regex = new RegExp(`^\\d{${length}}$`);
    return regex.test(otp);
}

module.exports = {
    isValidEmail,
    isValidPhone,
    isValidPassword,
    isValidUUID,
    isValidURL,
    isValidISODate,
    isValidOTP,
};
