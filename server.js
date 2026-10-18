require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const pool = require("./db");
const session = require("express-session");
const { rateLimit } = require("express-rate-limit");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
    console.error("Set a SESSION_SECRET of at least 32 characters in .env");
    process.exit(1);
}

if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
    console.error("Set ADMIN_EMAIL and ADMIN_PASSWORD in .env");
    process.exit(1);
}

// Security headers. CSP will be configured separately after frontend testing.
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));

app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "100kb" }));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { message: "Too many login attempts. Please try again in 15 minutes." }
});

const supportLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { message: "Too many support messages. Please try again later." }
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { message: "Too many registration attempts. Please try again later." }
});


app.use(session({
    store: new pgSession({
        pool,
        createTableIfMissing: true
    }),
    name: "maa.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: isProduction,
        maxAge: 1000 * 60 * 60
    }
}));

const publicDir = path.join(__dirname, "public");
const uploadDir = path.join(publicDir, "uploads");

fs.mkdirSync(uploadDir, { recursive: true });

app.use(express.static(publicDir));

/*
 * DEMO STORAGE
 * Data will disappear when the server restarts.
 * Add a permanent database before public launch.
 */

const users = [];
const products = [];
const orders = [];

let nextProductId = 1;
let nextOrderId = 1;
let nextUserId = 1;

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, crypto.randomUUID() + ext);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 3 * 1024 * 1024,
        files: 1
    },
    fileFilter: (req, file, cb) => {
        const allowed = [
            "image/jpeg",
            "image/png",
            "image/webp"
        ];

        if (!allowed.includes(file.mimetype)) {
            return cb(new Error("Upload JPG, PNG or WebP images only."));
        }

        cb(null, true);
    }
});


function validateUploadedImage(req, res, next) {
    if (!req.file) return next();

    let fd;

    try {
        fd = fs.openSync(req.file.path, "r");
        const header = Buffer.alloc(12);
        const bytesRead = fs.readSync(fd, header, 0, 12, 0);
        fs.closeSync(fd);
        fd = undefined;

        const ext = path.extname(req.file.originalname).toLowerCase();

        const isJpeg =
            bytesRead >= 3 &&
            header[0] === 0xff &&
            header[1] === 0xd8 &&
            header[2] === 0xff;

        const isPng =
            bytesRead >= 8 &&
            header.subarray(0, 8).equals(
                Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
            );

        const isWebp =
            bytesRead >= 12 &&
            header.toString("ascii", 0, 4) === "RIFF" &&
            header.toString("ascii", 8, 12) === "WEBP";

        const valid =
            (req.file.mimetype === "image/jpeg" &&
                [".jpg", ".jpeg"].includes(ext) && isJpeg) ||
            (req.file.mimetype === "image/png" &&
                ext === ".png" && isPng) ||
            (req.file.mimetype === "image/webp" &&
                ext === ".webp" && isWebp);

        if (!valid) {
            try { fs.unlinkSync(req.file.path); } catch (_) {}
            return res.status(400).json({
                message: "File content must match a supported image type."
            });
        }

        return next();
    } catch (_) {
        if (fd !== undefined) {
            try { fs.closeSync(fd); } catch (_) {}
        }
        try {
            if (fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
        } catch (_) {}

        return res.status(400).json({
            message: "Could not validate the uploaded image."
        });
    }
}

function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            message: "Please log in first."
        });
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user ||
        req.session.user.role !== "admin") {
        return res.status(403).json({
            message: "Admin access required."
        });
    }

    next();
}

function publicProduct(product) {
    return {
        id: product.id,
        name: product.name,
        description: product.description,
        price: product.price,
        image: product.image,
        stock: product.stock
    };
}

app.get("/api/status", (req, res) => {
    res.json({
        store: "MAA JAHNABI RESALE HUB",
        status: "running"
    });
});

/* REGISTER: POSTGRESQL */

app.post("/api/register", registerLimiter, async (req, res) => {
    try {
        const username = String(req.body.username || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!username || username.length > 60 ||
            !email || email.length > 254 ||
            password.length < 8 || password.length > 128) {
            return res.status(400).json({
                message: "Enter a valid username, email and password (8–128 characters)."
            });
        }

        if (email === String(process.env.ADMIN_EMAIL || "").trim().toLowerCase()) {
            return res.status(409).json({
                message: "This email is reserved for the store administrator."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        try {
            await pool.query(
                "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)",
                [username, email, passwordHash]
            );
        } catch (error) {
            if (error.code === "23505") {
                return res.status(409).json({
                    message: "This email is already registered."
                });
            }
            throw error;
        }

        return res.status(201).json({
            message: "Registration successful. Please log in."
        });
    } catch (error) {
        console.error("Registration error:", error.message);
        return res.status(500).json({ message: "Server error." });
    }
});

/* LOGIN: POSTGRESQL CUSTOMER OR ENVIRONMENT-BASED ADMIN */

app.post("/api/login", loginLimiter, async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");
        const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();

        let account;

        if (email === adminEmail &&
            password === process.env.ADMIN_PASSWORD) {
            account = {
                id: "admin",
                username: "Administrator",
                email,
                role: "admin"
            };
        } else {
            const result = await pool.query(
                "SELECT id, name, email, password_hash FROM users WHERE email = $1",
                [email]
            );

            const user = result.rows[0];

            if (!user || !(await bcrypt.compare(password, user.password_hash))) {
                return res.status(401).json({
                    message: "Invalid email or password."
                });
            }

            account = {
                id: Number(user.id),
                username: user.name,
                email: user.email,
                role: "customer"
            };
        }

        req.session.regenerate(error => {
            if (error) {
                console.error("Session regeneration error:", error.message);
                return res.status(500).json({
                    message: "Could not create a login session."
                });
            }

            req.session.user = account;

            req.session.save(error => {
                if (error) {
                    console.error("Session save error:", error.message);
                    return res.status(500).json({
                        message: "Could not save login session."
                    });
                }

                return res.json({
                    message: "Login successful!",
                    user: account
                });
            });
        });
    } catch (error) {
        console.error("Login error:", error.message);
        return res.status(500).json({ message: "Server error." });
    }
});

/* CUSTOMER SUPPORT CONTACT FORM */

app.post("/api/support", supportLimiter, requireLogin, async (req, res) => {
    try {
        const user = req.session.user;

        if (user.role !== "customer" || !Number.isInteger(Number(user.id))) {
            return res.status(403).json({
                message: "Customer account required."
            });
        }

        const subject = String(req.body.subject || "").trim();
        const message = String(req.body.message || "").trim();

        if (subject.length < 3 || subject.length > 120 ||
            message.length < 10 || message.length > 3000) {
            return res.status(400).json({
                message: "Subject must be 3–120 characters and message 10–3000 characters."
            });
        }

        await pool.query(
            `INSERT INTO support_messages
                (user_id, customer_name, customer_email, subject, message)
             VALUES ($1, $2, $3, $4, $5)`,
            [Number(user.id), String(user.username || "Customer").slice(0, 60),
             String(user.email || "").slice(0, 254), subject, message]
        );

        return res.status(201).json({
            message: "Your support message was sent successfully."
        });
    } catch (error) {
        console.error("Support message error:", error.message);
        return res.status(500).json({
            message: "Could not send your support message. Please try again later."
        });
    }
});

/* CURRENT USER */

app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            message: "Please log in."
        });
    }

    res.json(req.session.user);
});

/* LOGOUT */

app.post("/api/logout", (req, res) => {
    req.session.destroy(error => {
        if (error) {
            return res.status(500).json({
                message: "Could not log out."
            });
        }

        res.clearCookie("maa.sid");
        res.json({
            message: "Logged out successfully."
        });
    });
});

/* PUBLIC PRODUCT LIST: POSTGRESQL */

app.get("/api/products", async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, name, description, price, stock, image_url, category, discount_percent FROM products ORDER BY created_at DESC, id DESC"
        );

        res.json(result.rows.map(row => ({
            id: Number(row.id),
            name: row.name,
            description: row.description,
            price: Number(row.price),
            stock: Number(row.stock),
            image: row.image_url,
            category: row.category,
            discountPercent: Number(row.discount_percent || 0)
        })));
    } catch (error) {
        console.error("Product listing error:", error.message);
        res.status(500).json({ message: "Could not load products." });
    }
});

/* ADMIN: ADD PRODUCT WITH PHOTO */

app.post(
    "/api/admin/products",
    requireAdmin,
    upload.single("image"),
    validateUploadedImage,
    async (req, res) => {
        try {
            const name = String(req.body.name || "").trim();
            const description = String(req.body.description || "").trim();
            const price = Number(req.body.price);
            const stock = Number(req.body.stock ?? 1);
            const discountPercent = Number(req.body.discountPercent ?? 0);
            const category = String(req.body.category || "Others");
            const allowedCategories = [
                "Mobile", "Laptop", "Computer", "Tablet", "Others"
            ];

            if (!name || name.length > 120 ||
                !description || description.length > 2000 ||
                !Number.isFinite(price) || price <= 0 ||
                !Number.isInteger(stock) || stock < 0 ||
                !Number.isFinite(discountPercent) ||
                discountPercent < 0 || discountPercent > 90 ||
                !allowedCategories.includes(category)) {
                if (req.file) fs.unlinkSync(req.file.path);

                return res.status(400).json({
                    message: "Enter a valid name, description, price and stock."
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    message: "Please upload a product photo."
                });
            }

            const image = "/uploads/" + req.file.filename;

            const result = await pool.query(
                `INSERT INTO products
                 (name, description, price, stock, image_url, category, discount_percent)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 RETURNING id, name, description, price, stock, image_url, category, discount_percent`,
                [name, description, price, stock, image, category, discountPercent]
            );

            const row = result.rows[0];
            const product = {
                id: Number(row.id),
                name: row.name,
                description: row.description,
                price: Number(row.price),
                stock: Number(row.stock),
                image: row.image_url,
                category: row.category,
                discountPercent: Number(row.discount_percent || 0)
            };

            return res.status(201).json({
                message: "Product added successfully!",
                product
            });
        } catch (error) {
            if (req.file && fs.existsSync(req.file.path)) {
                try { fs.unlinkSync(req.file.path); } catch (_) {}
            }

            console.error("Add product error:", error.message);
            return res.status(500).json({
                message: "Could not add product."
            });
        }
    }
);

/* ADMIN: EDIT PRODUCT */

app.put(
    "/api/admin/products/:id",
    requireAdmin,
    upload.single("image"),
    validateUploadedImage,
    async (req, res) => {
        let newImagePath = req.file ? req.file.path : null;

        try {
            const id = Number(req.params.id);

            if (!Number.isSafeInteger(id) || id <= 0) {
                if (req.file) fs.unlinkSync(req.file.path);
                return res.status(400).json({
                    message: "Invalid product ID."
                });
            }

            const existing = await pool.query(
                "SELECT id, name, description, price, stock, image_url, category, discount_percent FROM products WHERE id = $1",
                [id]
            );

            if (existing.rows.length === 0) {
                if (req.file) fs.unlinkSync(req.file.path);
                return res.status(404).json({
                    message: "Product not found."
                });
            }

            const old = existing.rows[0];
            const name = String(req.body.name ?? old.name).trim();
            const description = String(
                req.body.description ?? old.description
            ).trim();
            const price = Number(req.body.price ?? old.price);
            const stock = Number(req.body.stock ?? old.stock);
            const discountPercent = Number(
                req.body.discountPercent ?? old.discount_percent ?? 0
            );
            const image = req.file
                ? "/uploads/" + req.file.filename
                : old.image_url;
            const category = String(req.body.category ?? old.category ?? "Others");
            const allowedCategories = [
                "Mobile", "Laptop", "Computer", "Tablet", "Others"
            ];

            if (!name || name.length > 120 ||
                !description || description.length > 2000 ||
                !Number.isFinite(price) || price <= 0 ||
                !Number.isInteger(stock) || stock < 0 ||
                !Number.isFinite(discountPercent) ||
                discountPercent < 0 || discountPercent > 90 ||
                !allowedCategories.includes(category)) {
                if (req.file) fs.unlinkSync(req.file.path);
                return res.status(400).json({
                    message: "Invalid product details."
                });
            }

            const result = await pool.query(
                `UPDATE products
                 SET name = $1, description = $2, price = $3,
                     stock = $4, image_url = $5, category = $6,
                     discount_percent = $7
                 WHERE id = $8
                 RETURNING id, name, description, price, stock, image_url, category, discount_percent`,
                [name, description, price, stock, image, category, discountPercent, id]
            );

            const row = result.rows[0];

            if (req.file && old.image_url &&
                old.image_url.startsWith("/uploads/")) {
                const oldPath = path.join(
                    publicDir,
                    old.image_url.replace(/^\/+/, "")
                );

                if (fs.existsSync(oldPath)) {
                    try { fs.unlinkSync(oldPath); } catch (_) {}
                }
            }

            newImagePath = null;

            return res.json({
                message: "Product updated successfully.",
                product: {
                    id: Number(row.id),
                    name: row.name,
                    description: row.description,
                    price: Number(row.price),
                    stock: Number(row.stock),
                    image: row.image_url,
                    category: row.category,
                    discountPercent: Number(row.discount_percent || 0)
                }
            });
        } catch (error) {
            if (newImagePath && fs.existsSync(newImagePath)) {
                try { fs.unlinkSync(newImagePath); } catch (_) {}
            }

            console.error("Edit product error:", error.message);
            return res.status(500).json({
                message: "Could not update product."
            });
        }
    }
);

/* ADMIN: DELETE PRODUCT */

app.delete(
    "/api/admin/products/:id",
    requireAdmin,
    async (req, res) => {
        try {
            const id = Number(req.params.id);

            if (!Number.isSafeInteger(id) || id <= 0) {
                return res.status(400).json({
                    message: "Invalid product ID."
                });
            }

            const result = await pool.query(
                "DELETE FROM products WHERE id = $1 RETURNING image_url",
                [id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    message: "Product not found."
                });
            }

            const image = result.rows[0].image_url;

            if (image && image.startsWith("/uploads/")) {
                const imagePath = path.join(
                    publicDir,
                    image.replace(/^\/+/, "")
                );

                if (fs.existsSync(imagePath)) {
                    try { fs.unlinkSync(imagePath); } catch (_) {}
                }
            }

            return res.json({
                message: "Product deleted successfully."
            });
        } catch (error) {
            if (error.code === "23503") {
                return res.status(409).json({
                    message: "This product has existing orders and cannot be deleted."
                });
            }

            console.error("Delete product error:", error.message);
            return res.status(500).json({
                message: "Could not delete product."
            });
        }
    }
);

/* CUSTOMER: PLACE COD ORDER *//* CUSTOMER: PLACE COD ORDER */
/* CUSTOMER: PLACE COD ORDER */

app.post("/api/orders", requireLogin, async (req, res) => {
    const user = req.session.user;

    if (!user || user.role !== "customer") {
        return res.status(403).json({
            message: "Customer account required to place an order."
        });
    }

    const productId = Number(req.body.productId);
    const quantity = Number(req.body.quantity);

    const customerName = String(req.body.customerName || "").trim();
    const phone = String(req.body.phone || "").trim();
    const addressLine = String(req.body.addressLine || "").trim();
    const city = String(req.body.city || "").trim();
    const state = String(req.body.state || "").trim();
    const pincode = String(req.body.pincode || "").trim();

    if (
        !Number.isSafeInteger(productId) || productId < 1 ||
        !Number.isInteger(quantity) || quantity < 1 || quantity > 20 ||
        customerName.length < 2 || customerName.length > 100 ||
        !/^[0-9+()\-\s]{8,20}$/.test(phone) ||
        addressLine.length < 5 || addressLine.length > 500 ||
        city.length < 2 || city.length > 100 ||
        state.length < 2 || state.length > 100 ||
        !/^[0-9]{6}$/.test(pincode)
    ) {
        return res.status(400).json({
            message: "Enter a valid name, phone, street address, city, state and 6-digit PIN code."
        });
    }

    const address = `${addressLine}, ${city}, ${state} - ${pincode}`;
    const client = await pool.connect();
    let transactionStarted = false;

    try {
        await client.query("BEGIN");
        transactionStarted = true;

        const productResult = await client.query(
            `SELECT id, name, price, stock, discount_percent
             FROM products
             WHERE id = $1
             FOR UPDATE`,
            [productId]
        );

        if (productResult.rows.length === 0) {
            await client.query("ROLLBACK");
            transactionStarted = false;
            return res.status(400).json({
                message: "Product not found."
            });
        }

        const product = productResult.rows[0];
        const discountPercent = Number(product.discount_percent || 0);
        const unitPrice = Number(
            (Number(product.price) * (1 - discountPercent / 100)).toFixed(2)
        );

        if (quantity > Number(product.stock)) {
            await client.query("ROLLBACK");
            transactionStarted = false;
            return res.status(400).json({
                message: "Not enough stock available."
            });
        }

        const orderResult = await client.query(
            `INSERT INTO orders
             (
                 user_id, product_id, quantity, unit_price,
                 phone, address, customer_name, address_line,
                 city, state, pincode, status, payment_method
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING id, user_id, product_id, quantity, unit_price,
                       phone, address, customer_name, address_line,
                       city, state, pincode, status, payment_method, created_at`,
            [
                user.id,
                product.id,
                quantity,
                unitPrice,
                phone,
                address,
                customerName,
                addressLine,
                city,
                state,
                pincode,
                "Pending",
                "COD"
            ]
        );

        await client.query(
            `UPDATE products
             SET stock = stock - $1
             WHERE id = $2`,
            [quantity, product.id]
        );

        await client.query("COMMIT");
        transactionStarted = false;

        const savedOrder = orderResult.rows[0];

        return res.status(201).json({
            message: "Order placed successfully!",
            order: {
                id: Number(savedOrder.id),
                userId: Number(savedOrder.user_id),
                productId: Number(savedOrder.product_id),
                productName: product.name,
                quantity: Number(savedOrder.quantity),
                unitPrice: Number(savedOrder.unit_price),
                total: Number(
                    (Number(savedOrder.unit_price) * Number(savedOrder.quantity)).toFixed(2)
                ),
                customerName: savedOrder.customer_name,
                phone: savedOrder.phone,
                address: savedOrder.address,
                addressLine: savedOrder.address_line,
                city: savedOrder.city,
                state: savedOrder.state,
                pincode: savedOrder.pincode,
                status: savedOrder.status,
                paymentMethod: savedOrder.payment_method,
                createdAt: savedOrder.created_at
            }
        });

    } catch (error) {
        if (transactionStarted) {
            try {
                await client.query("ROLLBACK");
            } catch (_) {}
        }

        console.error("Place order error:", error.message);

        return res.status(500).json({
            message: "Could not place order. Please try again."
        });

    } finally {
        client.release();
    }
});


/* CUSTOMER: VIEW OWN ORDERS */

app.get("/api/my-orders", requireLogin, async (req, res) => {
    if (req.session.user.role !== "customer") {
        return res.status(403).json({
            message: "Customer account required."
        });
    }

    try {
        const result = await pool.query(
            `SELECT o.id, o.user_id, o.product_id, o.quantity,
                    o.unit_price, o.phone, o.address, o.status,
                    o.payment_method, o.created_at,
                    o.customer_name, o.customer_email AS email,
                    o.product_name
             FROM orders o
             WHERE o.user_id = $1
             ORDER BY o.created_at DESC, o.id DESC`,
            [req.session.user.id]
        );

        res.json(result.rows.map(row => ({
            id: Number(row.id),
            userId: Number(row.user_id),
            customerName: row.customer_name,
            email: row.email,
            phone: row.phone,
            address: row.address,
            productId: Number(row.product_id),
            productName: row.product_name,
            quantity: Number(row.quantity),
            unitPrice: Number(row.unit_price),
            total: Number((Number(row.unit_price) * Number(row.quantity)).toFixed(2)),
            paymentMethod: row.payment_method,
            status: row.status,
            createdAt: row.created_at
        })));
    } catch (error) {
        console.error("Customer orders error:", error.message);
        res.status(500).json({
            message: "Could not load your orders."
        });
    }
});



/* CUSTOMER: CANCEL OWN ELIGIBLE ORDER */

app.post("/api/my-orders/:id/cancel", requireLogin, async (req, res) => {
    if (!req.session.user || req.session.user.role !== "customer") {
        return res.status(403).json({
            message: "Customer account required."
        });
    }

    const orderId = Number(req.params.id);

    if (!Number.isSafeInteger(orderId) || orderId < 1) {
        return res.status(400).json({
            message: "Invalid order ID."
        });
    }

    let client;
    let transactionStarted = false;

    try {
        client = await pool.connect();
        await client.query("BEGIN");
        transactionStarted = true;

        const result = await client.query(
            `SELECT id, user_id, product_id, quantity, status, payment_method
             FROM orders
             WHERE id = $1 AND user_id = $2
             FOR UPDATE`,
            [orderId, req.session.user.id]
        );

        if (result.rows.length === 0) {
            await client.query("ROLLBACK");
            transactionStarted = false;
            return res.status(404).json({
                message: "Order not found."
            });
        }

        const order = result.rows[0];

        if (order.status === "Cancelled") {
            await client.query("ROLLBACK");
            transactionStarted = false;
            return res.status(409).json({
                message: "This order has already been cancelled."
            });
        }

        if (!["Pending", "Confirmed"].includes(order.status)) {
            await client.query("ROLLBACK");
            transactionStarted = false;
            return res.status(409).json({
                message: "This order can no longer be cancelled online."
            });
        }

        if (String(order.payment_method || "COD").trim().toUpperCase() !== "COD") {
            await client.query("ROLLBACK");
            transactionStarted = false;
            return res.status(409).json({
                message: "Please contact support to cancel this paid order and arrange any applicable refund."
            });
        }

        const stockUpdate = await client.query(
            `UPDATE products
             SET stock = stock + $1
             WHERE id = $2`,
            [order.quantity, order.product_id]
        );

        if (stockUpdate.rowCount !== 1) {
            throw new Error("Product stock could not be restored.");
        }

        await client.query(
            `UPDATE orders
             SET status = 'Cancelled'
             WHERE id = $1`,
            [order.id]
        );

        await client.query("COMMIT");
        transactionStarted = false;

        return res.json({
            message: "Order cancelled successfully.",
            orderId: Number(order.id),
            status: "Cancelled"
        });
    } catch (error) {
        if (transactionStarted && client) {
            try {
                await client.query("ROLLBACK");
            } catch (_) {}
        }

        console.error("Customer order cancellation error:", error.message);
        return res.status(500).json({
            message: "Could not cancel the order. Please try again."
        });
    } finally {
        if (client) client.release();
    }
});


/* ADMIN: VIEW ALL ORDERS */

app.get("/api/admin/orders", requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT o.id, o.user_id, o.product_id, o.quantity,
                    o.unit_price, o.phone, o.address, o.status,
                    o.payment_method, o.created_at,
                    o.customer_name, o.customer_email AS email,
                    o.product_name
             FROM orders o
             ORDER BY o.created_at DESC, o.id DESC`
        );

        res.json(result.rows.map(row => ({
            id: Number(row.id),
            userId: Number(row.user_id),
            customerName: row.customer_name,
            email: row.email,
            phone: row.phone,
            address: row.address,
            productId: Number(row.product_id),
            productName: row.product_name,
            quantity: Number(row.quantity),
            unitPrice: Number(row.unit_price),
            total: Number((Number(row.unit_price) * Number(row.quantity)).toFixed(2)),
            paymentMethod: row.payment_method,
            status: row.status,
            createdAt: row.created_at
        })));
    } catch (error) {
        console.error("Admin orders error:", error.message);
        res.status(500).json({
            message: "Could not load orders."
        });
    }
});


/* ADMIN: UPDATE ORDER STATUS */

app.patch("/api/admin/orders/:id", requireAdmin, async (req, res) => {
    const orderId = Number(req.params.id);

    if (!Number.isSafeInteger(orderId) || orderId < 1) {
        return res.status(400).json({
            message: "Invalid order ID."
        });
    }

    const allowedStatuses = [
        "Pending",
        "Confirmed",
        "Shipped",
        "Delivered",
        "Cancelled"
    ];

    const status = String(req.body.status || "");

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
            message: "Invalid order status."
        });
    }

    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const result = await client.query(
            `SELECT id, product_id, quantity, status, payment_method
             FROM orders
             WHERE id = $1
             FOR UPDATE`,
            [orderId]
        );

        if (result.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).json({
                message: "Order not found."
            });
        }

        const order = result.rows[0];

        const allowedTransitions = {
            Pending: ["Confirmed", "Cancelled"],
            Confirmed: ["Shipped", "Cancelled"],
            Shipped: ["Delivered"],
            Delivered: [],
            Cancelled: []
        };

        if (
            status !== order.status &&
            !(allowedTransitions[order.status] || []).includes(status)
        ) {
            await client.query("ROLLBACK");
            return res.status(409).json({
                message: "This order status transition is not allowed."
            });
        }

        if (status !== order.status && status === "Cancelled") {
            if (
                String(order.payment_method || "COD").trim().toUpperCase()
                !== "COD"
            ) {
                await client.query("ROLLBACK");
                return res.status(409).json({
                    message: "Paid orders cannot be cancelled here. Verify the refund process with support first."
                });
            }

            const stockUpdate = await client.query(
                `UPDATE products
                 SET stock = stock + $1
                 WHERE id = $2`,
                [order.quantity, order.product_id]
            );

            if (stockUpdate.rowCount !== 1) {
                throw new Error("Product stock could not be restored.");
            }
        }

        const updated = await client.query(
            `UPDATE orders
             SET status = $1
             WHERE id = $2
             RETURNING id, user_id, product_id, quantity,
                       unit_price, phone, address, status,
                       payment_method, created_at`,
            [status, orderId]
        );

        await client.query("COMMIT");

        const row = updated.rows[0];

        res.json({
            message: "Order status updated.",
            order: {
                id: Number(row.id),
                userId: Number(row.user_id),
                productId: Number(row.product_id),
                quantity: Number(row.quantity),
                unitPrice: Number(row.unit_price),
                total: Number((Number(row.unit_price) * Number(row.quantity)).toFixed(2)),
                phone: row.phone,
                address: row.address,
                status: row.status,
                paymentMethod: row.payment_method,
                createdAt: row.created_at
            }
        });
    } catch (error) {
        try {
            await client.query("ROLLBACK");
        } catch (_) {}

        console.error("Update order status error:", error.message);
        res.status(500).json({
            message: "Could not update order status."
        });
    } finally {
        client.release();
    }
});


/* ADMIN: DASHBOARD STATISTICS */

app.get("/api/admin/stats", requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                (SELECT COUNT(*) FROM products)::int AS total_products,
                (SELECT COUNT(*) FROM orders)::int AS total_orders,
                (SELECT COUNT(*) FROM orders
                 WHERE status = 'Pending')::int AS pending_orders,
                (SELECT COUNT(*) FROM users)::int AS total_customers`
        );

        const row = result.rows[0];

        res.json({
            totalProducts: row.total_products,
            totalOrders: row.total_orders,
            pendingOrders: row.pending_orders,
            totalCustomers: row.total_customers
        });
    } catch (error) {
        console.error("Admin statistics error:", error.message);
        res.status(500).json({
            message: "Could not load dashboard statistics."
        });
    }
});

/* UPLOAD ERROR HANDLING */

app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        return res.status(400).json({
            message: error.code === "LIMIT_FILE_SIZE"
                ? "Image must be 3 MB or smaller."
                : "Image upload failed."
        });
    }

    if (error) {
        if (error.message === "Upload JPG, PNG or WebP images only.") {
            return res.status(400).json({
                message: error.message
            });
        }

        console.error("Request error:", error.message);
        return res.status(500).json({
            message: "Request failed. Please try again."
        });
    }

    next();
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(
        `MAA JAHNABI RESALE HUB running at http://127.0.0.1:${PORT}`
    );
});
