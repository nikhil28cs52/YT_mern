const { ValidationError } = require('joi');

const errorHandler = (error, req, res, next) => {
    // Default error
    let status = 500;
    let data = {
        message: 'Internal Server Error'
    };

    if (error instanceof ValidationError) {
        status = 400; // Setting the status to 400 for validation errors
        data.message = error.message;
    } else if (error.status) {
        status = error.status;
        data.message = error.message || data.message; // Use error.message if available
    } else if (error.message) {
        data.message = error.message;
    }

    return res.status(status).json(data);
};

module.exports = errorHandler;
