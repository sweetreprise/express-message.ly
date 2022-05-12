const express = require("express");
const router = new express.Router();
const ExpressError = require('../expressError');
const User = require("../models/user");
const Message = require("../models/message");
const {ensureLoggedIn, ensureCorrectUser} = require("../middleware/auth");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get('/:id', ensureLoggedIn, async function(req, res, next) {
    try {
        const msg = await Message.get(req.params.id);
        if(req.user.username !== msg.from_user.username || req.user.username !== msg.to_user.username) {
            throw new ExpressError('Sorry, you are unauthorized to view this page', 404);
        }

        return res.json({ msg });
    } catch(e) {
        return next(e);
    }
});


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post('/', ensureLoggedIn, async function(req, res, next) {
    try {
        const { to_username, body } = req.body;
        const msg = await Message.create(req.user.username, to_username, body);
        return res.json({ msg })
    } catch(e) {
        return next(e);
    }
});


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post('/:id/read', ensureLoggedIn, async function(req, res, next) {
    try {
        const msg = await Message.get(req.params.id);
        if(req.user.username !== msg.to_user.username) {
            throw new ExpressError('Sorry, you are unauthorized to view this page', 404);
        }
        const readMsg = await Message.markRead(req.params.id);
        return res.json({ message: { id: req.params.id, read_at: readMsg.read_at }})
    } catch(e) {
        return next(e);
    }
});

