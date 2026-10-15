package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int
	Username     string
	PasswordHash string
	Role         string
}

type Order struct {
	ID         int
	ItemName   string
	Quantity   int
	Note       string
	Status     string
	UserID     int
	OwnerName  string
	CreatedAt  time.Time
	UnitPrice  int
	TotalPrice int
}

type Session struct {
	UserID   int
	Username string
	Role     string
	Expires  time.Time
}

var (
	db           *sql.DB
	sessions     = make(map[string]Session)
	sessionMutex sync.Mutex
	tmpl         *template.Template
)

func getItemPrice(itemName string) int {
	switch itemName {
	case "ชาไทยเย็นสูตรเข้มข้น (Thai Iced Tea)":
		return 45
	case "ชาเขียวมัจฉะลาเต้ (Matcha Green Tea)":
		return 50
	case "อเมริกาโน่เย็น (Iced Americano)":
		return 50
	case "คาปูชิโน่ฟองนมนุ่ม (Cappuccino)":
		return 55
	case "ชานมไข่มุกบราวน์ซูการ์ (Boba Milk Tea)":
		return 45
	case "โกโก้เข้มข้นเย็น (Dark Cocoa)":
		return 45
	case "ชามะนาวน้ำผึ้งสดชื่น (Honey Lemon Tea)":
		return 40
	default:
		return 45
	}
}

func main() {
	var err error

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "root:@tcp(127.0.0.1:3306)/go_project?parseTime=true"
	}

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("ไม่สามารถเชื่อมต่อฐานข้อมูลได้:", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("ไม่สามารถสื่อสารกับ MySQL ได้:", err)
	}
	fmt.Println("เชื่อมต่อกับฐานข้อมูล MySQL สำเร็จ!")

	initDefaultAdmin()

	tmpl = template.Must(template.New("app").Parse(htmlTemplates))

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)

	mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))
	mux.HandleFunc("/orders/create", requireAuth(createOrderHandler))
	mux.HandleFunc("/orders/cancel", requireAuth(cancelOrderHandler))

	mux.HandleFunc("/admin", requireRole("admin", adminHandler))

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      securityHeaders(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Println("ร้านเครื่องดื่มคาเฟ่กำลังออนไลน์ที่พอร์ต :" + port)
	log.Fatal(server.ListenAndServe())
}

func initDefaultAdmin() {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
	if err != nil || count == 0 {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", "admin", string(hashedPassword), "admin")
	}
	fmt.Println("สร้างบัญชีผู้ดูแลระบบเริ่มต้นสำเร็จ -> Username: admin | Password: admin123")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok := getSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := getSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if sess.Role != role {
			http.Error(w, "403 Forbidden - คุณไม่มีสิทธิ์เข้าถึงหน้าจัดการร้านค้า", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func getSession(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return Session{}, false
	}
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	sess, exists := sessions[cookie.Value]
	if !exists || time.Now().After(sess.Expires) {
		return Session{}, false
	}
	return sess, true
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess, loggedIn := getSession(r)
	if loggedIn {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"LoggedIn": loggedIn,
		"Username": sess.Username,
	})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl.ExecuteTemplate(w, "register.html", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "ข้อมูลไม่ถูกต้อง", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	role := "user"

	if len(username) < 3 || len(password) < 4 {
		tmpl.ExecuteTemplate(w, "register.html", map[string]string{"Error": "ชื่อผู้ใช้ต้องมีอย่างน้อย 3 ตัวอักษร และรหัสผ่านต้องมีอย่างน้อย 4 ตัวอักษร"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "เกิดข้อผิดพลาดในการเข้ารหัส", http.StatusInternalServerError)
		return
	}

	stmt, err := db.Prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
	if err != nil {
		http.Error(w, "ข้อผิดพลาดระบบฐานข้อมูล", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, string(hashedPassword), role)
	if err != nil {
		tmpl.ExecuteTemplate(w, "register.html", map[string]string{"Error": "ชื่อผู้ใช้านี้ถูกใช้งานแล้ว กรุณาใช้ชื่ออื่น"})
		return
	}

	http.Redirect(w, r, "/login?registered=1", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		successMsg := ""
		if r.URL.Query().Get("registered") == "1" {
			successMsg = "ลงทะเบียนสำเร็จแล้ว! กรุณาเข้าสู่ระบบเพื่อสั่งเครื่องดื่ม"
		}
		tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Success": successMsg})
		return
	}

	r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	var user User
	err := db.QueryRow("SELECT id, username, password_hash, role FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role)

	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"})
		return
	}

	sessionID, _ := newSessionID()
	expires := time.Now().Add(1 * time.Hour)

	sessionMutex.Lock()
	sessions[sessionID] = Session{UserID: user.ID, Username: user.Username, Role: user.Role, Expires: expires}
	sessionMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		sessionMutex.Lock()
		delete(sessions, cookie.Value)
		sessionMutex.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := getSession(r)

	rows, err := db.Query("SELECT id, item_name, quantity, note, status, created_at FROM orders WHERE user_id = ? ORDER BY id DESC", sess.UserID)
	if err != nil {
		http.Error(w, "ไม่สามารถดึงข้อมูลคำสั่งซื้อได้", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []Order
	pendingCount := 0
	brewingCount := 0
	completedCount := 0
	grandTotalAmount := 0

	for rows.Next() {
		var o Order
		rows.Scan(&o.ID, &o.ItemName, &o.Quantity, &o.Note, &o.Status, &o.CreatedAt)
		o.UnitPrice = getItemPrice(o.ItemName)
		o.TotalPrice = o.UnitPrice * o.Quantity

		if o.Status != "cancelled" {
			grandTotalAmount += o.TotalPrice
		}

		orders = append(orders, o)
		switch o.Status {
		case "pending":
			pendingCount++
		case "baking", "brewing":
			brewingCount++
		case "completed":
			completedCount++
		}
	}

	tmpl.ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
		"Username":         sess.Username,
		"Role":             sess.Role,
		"Orders":           orders,
		"TotalOrders":      len(orders),
		"PendingOrders":    pendingCount,
		"BrewingOrders":    brewingCount,
		"CompletedCount":   completedCount,
		"GrandTotalAmount": grandTotalAmount,
	})
}

func createOrderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		sess, _ := getSession(r)
		r.ParseForm()
		itemName := strings.TrimSpace(r.FormValue("item_name"))
		qtyStr := r.FormValue("quantity")
		note := strings.TrimSpace(r.FormValue("note"))

		quantity, err := strconv.Atoi(qtyStr)
		if err != nil || quantity < 1 || quantity > 100 {
			quantity = 1
		}

		if itemName != "" {
			stmt, err := db.Prepare("INSERT INTO orders (item_name, quantity, note, user_id) VALUES (?, ?, ?, ?)")
			if err == nil {
				defer stmt.Close()
				stmt.Exec(itemName, quantity, note, sess.UserID)
			}
		}
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func cancelOrderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		sess, _ := getSession(r)
		r.ParseForm()
		orderID := r.FormValue("id")

		stmt, err := db.Prepare("UPDATE orders SET status = 'cancelled' WHERE id = ? AND user_id = ? AND status = 'pending'")
		if err == nil {
			defer stmt.Close()
			stmt.Exec(orderID, sess.UserID)
		}
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := getSession(r)

	if r.Method == http.MethodPost {
		r.ParseForm()
		orderID := r.FormValue("order_id")
		newStatus := r.FormValue("status")

		if newStatus == "pending" || newStatus == "baking" || newStatus == "completed" || newStatus == "cancelled" {
			stmt, err := db.Prepare("UPDATE orders SET status = ? WHERE id = ?")
			if err == nil {
				defer stmt.Close()
				stmt.Exec(newStatus, orderID)
			}
		}
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	rows, err := db.Query("SELECT orders.id, orders.item_name, orders.quantity, orders.note, orders.status, orders.created_at, users.username FROM orders JOIN users ON orders.user_id = users.id ORDER BY orders.id DESC")
	if err != nil {
		http.Error(w, "ข้อผิดพลาดระบบ", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var allOrders []Order
	totalRevenue := 0

	for rows.Next() {
		var o Order
		rows.Scan(&o.ID, &o.ItemName, &o.Quantity, &o.Note, &o.Status, &o.CreatedAt, &o.OwnerName)
		o.UnitPrice = getItemPrice(o.ItemName)
		o.TotalPrice = o.UnitPrice * o.Quantity

		if o.Status != "cancelled" {
			totalRevenue += o.TotalPrice
		}

		allOrders = append(allOrders, o)
	}

	var userCount int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)

	tmpl.ExecuteTemplate(w, "admin.html", map[string]interface{}{
		"Username":     sess.Username,
		"Orders":       allOrders,
		"TotalOrders":  len(allOrders),
		"TotalUsers":   userCount,
		"TotalRevenue": totalRevenue,
	})
}

const htmlTemplates = `
{{define "index.html"}}
<!DOCTYPE html>
<html lang="th">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Fresh Drinks & Cafe - ร้านเครื่องดื่มสดชื่น</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
	<style>
		body { background: #f0f7f4; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
		.hero-card { background: #ffffff; border-radius: 20px; box-shadow: 0 10px 30px rgba(46, 139, 87, 0.15); }
		.btn-cafe { background-color: #2a9d8f; color: white; border: none; }
		.btn-cafe:hover { background-color: #218377; color: white; }
	</style>
</head>
<body>
	<div class="container min-vh-100 d-flex flex-column justify-content-center align-items-center text-center">
		<div class="card hero-card p-5 border-0" style="max-width: 520px; width: 100%;">
			<div class="mb-3 text-success">
				<i class="fa-solid fa-mug-hot fa-4x" style="color: #2a9d8f;"></i>
			</div>
			<h2 class="fw-bold mb-2" style="color: #264653;">Fresh Drinks Cafe</h2>
			<p class="text-muted mb-4">สั่ง ชา กาแฟ และเครื่องดื่มสดชื่นผ่านระบบออนไลน์</p>
			<div class="d-grid gap-3">
				<a href="/login" class="btn btn-cafe btn-lg rounded-pill fw-bold shadow-sm"><i class="fa-solid fa-right-to-bracket me-2"></i>เข้าสู่ระบบสั่งเครื่องดื่ม</a>
				<a href="/register" class="btn btn-outline-success btn-lg rounded-pill fw-bold"><i class="fa-solid fa-user-plus me-2"></i>สมัครสมาชิกใหม่</a>
			</div>
		</div>
	</div>
</body>
</html>
{{end}}

{{define "register.html"}}
<!DOCTYPE html>
<html lang="th">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>สมัครสมาชิก - Fresh Drinks Cafe</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
	<style>
		body { background: #f0f7f4; }
		.card-box { background: white; border-radius: 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.08); }
	</style>
</head>
<body>
	<div class="container min-vh-100 d-flex flex-column justify-content-center align-items-center">
		<div class="card card-box border-0 p-4" style="max-width: 430px; width: 100%;">
			<div class="text-center mb-4">
				<i class="fa-solid fa-glass-water fa-3x mb-2" style="color: #2a9d8f;"></i>
				<h3 class="fw-bold" style="color: #264653;">สมัครสมาชิก</h3>
				<p class="text-muted small">สร้างบัญชีสำหรับสั่งซื้อเครื่องดื่ม</p>
			</div>
			{{if .Error}}
				<div class="alert alert-danger rounded-3" role="alert">
					<i class="fa-solid fa-circle-exclamation me-2"></i>{{.Error}}
				</div>
			{{end}}
			<form method="POST" action="/register">
				<div class="mb-3">
					<label class="form-label fw-semibold"><i class="fa-solid fa-user me-1 text-secondary"></i>ชื่อผู้ใช้งาน (Username)</label>
					<input type="text" name="username" class="form-control form-control-lg rounded-3" placeholder="ระบุอย่างน้อย 3 ตัวอักษร" required minlength="3">
				</div>
				<div class="mb-4">
					<label class="form-label fw-semibold"><i class="fa-solid fa-lock me-1 text-secondary"></i>รหัสผ่าน (Password)</label>
					<input type="password" name="password" class="form-control form-control-lg rounded-3" placeholder="ระบุอย่างน้อย 4 ตัวอักษร" required minlength="4">
				</div>
				<button type="submit" class="btn btn-lg w-100 rounded-3 fw-bold text-white mb-3" style="background-color: #2a9d8f;"><i class="fa-solid fa-paper-plane me-2"></i>ลงทะเบียนผู้ใช้</button>
			</form>
			<div class="text-center">
				<span class="text-muted me-1">มีบัญชีผู้ใช้อยูแล้ว?</span>
				<a href="/login" class="fw-bold text-decoration-none" style="color: #2a9d8f;">เข้าสู่ระบบ</a>
			</div>
		</div>
	</div>
</body>
</html>
{{end}}

{{define "login.html"}}
<!DOCTYPE html>
<html lang="th">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>เข้าสู่ระบบ - Fresh Drinks Cafe</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
	<style>
		body { background: #f0f7f4; }
		.card-box { background: white; border-radius: 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.08); }
	</style>
</head>
<body>
	<div class="container min-vh-100 d-flex flex-column justify-content-center align-items-center">
		<div class="card card-box border-0 p-4" style="max-width: 430px; width: 100%;">
			<div class="text-center mb-4">
				<i class="fa-solid fa-store fa-3x mb-2" style="color: #2a9d8f;"></i>
				<h3 class="fw-bold" style="color: #264653;">เข้าสู่ระบบร้านเครื่องดื่ม</h3>
				<p class="text-muted small">ยินดีต้อนรับสู่ระบบสั่งน้ำคาเฟ่</p>
			</div>
			{{if .Success}}
				<div class="alert alert-success rounded-3" role="alert">
					<i class="fa-solid fa-circle-check me-2"></i>{{.Success}}
				</div>
			{{end}}
			{{if .Error}}
				<div class="alert alert-danger rounded-3" role="alert">
					<i class="fa-solid fa-triangle-exclamation me-2"></i>{{.Error}}
				</div>
			{{end}}
			<form method="POST" action="/login">
				<div class="mb-3">
					<label class="form-label fw-semibold"><i class="fa-solid fa-user me-1 text-secondary"></i>ชื่อผู้ใช้</label>
					<input type="text" name="username" class="form-control form-control-lg rounded-3" placeholder="ระบุชื่อผู้ใช้" required>
				</div>
				<div class="mb-4">
					<label class="form-label fw-semibold"><i class="fa-solid fa-lock me-1 text-secondary"></i>รหัสผ่าน</label>
					<input type="password" name="password" class="form-control form-control-lg rounded-3" placeholder="ระบุรหัสผ่าน" required>
				</div>
				<button type="submit" class="btn btn-lg w-100 rounded-3 fw-bold text-white mb-3" style="background-color: #2a9d8f;"><i class="fa-solid fa-right-to-bracket me-2"></i>เข้าสู่ระบบ</button>
			</form>
			<div class="text-center">
				<span class="text-muted me-1">ยังไม่มีบัญชี?</span>
				<a href="/register" class="fw-bold text-decoration-none" style="color: #2a9d8f;">สมัครสมาชิกใหม่</a>
			</div>
		</div>
	</div>
</body>
</html>
{{end}}

{{define "dashboard.html"}}
<!DOCTYPE html>
<html lang="th">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>รายการสั่งซื้อของฉัน - Fresh Drinks Cafe</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
	<style>
		body { background: #f0f7f4; }
		.navbar-cafe { background-color: #2a9d8f; }
		.card-custom { border-radius: 16px; border: none; }
		.btn-admin-nav { background-color: #e76f51; color: white; border: 2px solid #ffffff; }
		.btn-admin-nav:hover { background-color: #d65a3b; color: white; }
	</style>
</head>
<body>
	<nav class="navbar navbar-expand-lg navbar-dark navbar-cafe shadow-sm py-3">
		<div class="container">
			<a class="navbar-brand fw-bold fs-4" href="/dashboard"><i class="fa-solid fa-mug-hot me-2"></i>Fresh Drinks Cafe</a>
			<div class="d-flex align-items-center text-white gap-2">
				<span class="me-2 fs-6">
					<i class="fa-solid fa-circle-user me-1"></i>คุณ <b>{{.Username}}</b>
					<span class="badge {{if eq .Role "admin"}}bg-danger{{else}}bg-warning text-dark{{end}} ms-1 fs-6">{{.Role}}</span>
				</span>
				{{if eq .Role "admin"}}
					<a href="/admin" class="btn btn-admin-nav fw-bold shadow-sm px-3"><i class="fa-solid fa-user-shield me-1"></i>ระบบจัดการร้าน Admin</a>
				{{end}}
				<a href="/logout" class="btn btn-outline-light"><i class="fa-solid fa-right-from-bracket me-1"></i>ออกจากระบบ</a>
			</div>
		</div>
	</nav>

	<div class="container my-4">
		<div class="row g-3 mb-4">
			<div class="col-md-3">
				<div class="card card-custom shadow-sm p-3 bg-white border-start border-primary border-4">
					<div class="d-flex align-items-center justify-content-between">
						<div>
							<div class="text-muted small">ออเดอร์ทั้งหมด</div>
							<h4 class="fw-bold mb-0 text-primary">{{.TotalOrders}} รายการ</h4>
						</div>
						<i class="fa-solid fa-wine-glass fa-2x text-primary opacity-50"></i>
					</div>
				</div>
			</div>
			<div class="col-md-3">
				<div class="card card-custom shadow-sm p-3 bg-white border-start border-warning border-4">
					<div class="d-flex align-items-center justify-content-between">
						<div>
							<div class="text-muted small">กำลังชงเครื่องดื่ม</div>
							<h4 class="fw-bold mb-0 text-warning">{{.BrewingOrders}} รายการ</h4>
						</div>
						<i class="fa-solid fa-blender fa-2x text-warning opacity-50"></i>
					</div>
				</div>
			</div>
			<div class="col-md-3">
				<div class="card card-custom shadow-sm p-3 bg-white border-start border-success border-4">
					<div class="d-flex align-items-center justify-content-between">
						<div>
							<div class="text-muted small">พร้อมเสิร์ฟแล้ว</div>
							<h4 class="fw-bold mb-0 text-success">{{.CompletedCount}} รายการ</h4>
						</div>
						<i class="fa-solid fa-circle-check fa-2x text-success opacity-50"></i>
					</div>
				</div>
			</div>
			<div class="col-md-3">
				<div class="card card-custom shadow-sm p-3 bg-white border-start border-info border-4">
					<div class="d-flex align-items-center justify-content-between">
						<div>
							<div class="text-muted small">ยอดรวมค่าเครื่องดื่ม</div>
							<h4 class="fw-bold mb-0 text-info">{{.GrandTotalAmount}} บาท</h4>
						</div>
						<i class="fa-solid fa-coins fa-2x text-info opacity-50"></i>
					</div>
				</div>
			</div>
		</div>

		<div class="row g-4">
			<div class="col-lg-4">
				<div class="card card-custom shadow-sm p-4 bg-white">
					<h5 class="fw-bold mb-3" style="color: #264653;"><i class="fa-solid fa-cart-plus me-2" style="color: #2a9d8f;"></i>สั่งซื้อเครื่องดื่มใหม่</h5>
					<form method="POST" action="/orders/create">
						<div class="mb-3">
							<label class="form-label fw-semibold">เมนูเครื่องดื่ม & ราคา</label>
							<select name="item_name" class="form-select rounded-3" required>
								<option value="" disabled selected>-- เลือกเมนูเครื่องดื่ม --</option>
								<option value="ชาไทยเย็นสูตรเข้มข้น (Thai Iced Tea)">ชาไทยเย็นสูตรเข้มข้น - 45 บาท</option>
								<option value="ชาเขียวมัจฉะลาเต้ (Matcha Green Tea)">ชาเขียวมัจฉะลาเต้ - 50 บาท</option>
								<option value="อเมริกาโน่เย็น (Iced Americano)">อเมริกาโน่เย็น - 50 บาท</option>
								<option value="คาปูชิโน่ฟองนมนุ่ม (Cappuccino)">คาปูชิโน่ฟองนมนุ่ม - 55 บาท</option>
								<option value="ชานมไข่มุกบราวน์ซูการ์ (Boba Milk Tea)">ชานมไข่มุกบราวน์ซูการ์ - 45 บาท</option>
								<option value="โกโก้เข้มข้นเย็น (Dark Cocoa)">โกโก้เข้มข้นเย็น - 45 บาท</option>
								<option value="ชามะนาวน้ำผึ้งสดชื่น (Honey Lemon Tea)">ชามะนาวน้ำผึ้งสดชื่น - 40 บาท</option>
							</select>
						</div>
						<div class="mb-3">
							<label class="form-label fw-semibold">จำนวน (แก้ว)</label>
							<input type="number" name="quantity" class="form-control rounded-3" value="1" min="1" max="100" required>
						</div>
						<div class="mb-3">
							<label class="form-label fw-semibold">ระดับความหวาน / รายละเอียดเพิ่มเติม</label>
							<textarea name="note" class="form-control rounded-3" rows="3" placeholder="เช่น หวานน้อย 50%, เพิ่มไข่มุก, แยกน้ำแข็ง"></textarea>
						</div>
						<button type="submit" class="btn w-100 rounded-3 fw-bold text-white" style="background-color: #2a9d8f;"><i class="fa-solid fa-paper-plane me-1"></i>ส่งคำสั่งซื้อ</button>
					</form>
				</div>
			</div>

			<div class="col-lg-8">
				<div class="card card-custom shadow-sm p-4 bg-white">
					<h5 class="fw-bold mb-3" style="color: #264653;"><i class="fa-solid fa-receipt me-2" style="color: #2a9d8f;"></i>ประวัติคำสั่งซื้อของคุณ</h5>
					<div class="table-responsive">
						<table class="table table-hover align-middle">
							<thead class="table-light">
								<tr>
									<th>รหัสออเดอร์</th>
									<th>เมนูเครื่องดื่ม</th>
									<th>ราคา/แก้ว</th>
									<th>จำนวน</th>
									<th>ราคารวม</th>
									<th>สถานะ</th>
									<th class="text-end">ยกเลิกออเดอร์</th>
								</tr>
							</thead>
							<tbody>
								{{range .Orders}}
								<tr>
									<td class="fw-bold text-muted">#ORD-{{.ID}}</td>
									<td class="fw-semibold">
										{{.ItemName}}
										{{if .Note}}<div class="text-muted small">({{.Note}})</div>{{end}}
									</td>
									<td>{{.UnitPrice}} ฿</td>
									<td class="text-center"><span class="badge bg-light text-dark border">{{.Quantity}} แก้ว</span></td>
									<td class="fw-bold text-success">{{.TotalPrice}} ฿</td>
									<td>
										{{if eq .Status "pending"}}
											<span class="badge bg-secondary rounded-pill px-2 py-1"><i class="fa-solid fa-clock me-1"></i>รอร้านยืนยัน</span>
										{{else if or (eq .Status "baking") (eq .Status "brewing")}}
											<span class="badge bg-warning text-dark rounded-pill px-2 py-1"><i class="fa-solid fa-blender me-1"></i>กำลังชง</span>
										{{else if eq .Status "completed"}}
											<span class="badge bg-success rounded-pill px-2 py-1"><i class="fa-solid fa-check me-1"></i>พร้อมเสิร์ฟ</span>
										{{else}}
											<span class="badge bg-danger rounded-pill px-2 py-1">ยกเลิกแล้ว</span>
										{{end}}
									</td>
									<td class="text-end">
										{{if eq .Status "pending"}}
										<form method="POST" action="/orders/cancel" class="d-inline" onsubmit="return confirm('คุณต้องการยกเลิกคำสั่งซื้อนี้ใช่หรือไม่?');">
											<input type="hidden" name="id" value="{{.ID}}">
											<button type="submit" class="btn btn-sm btn-outline-danger" title="ยกเลิกออเดอร์"><i class="fa-solid fa-xmark me-1"></i>ยกเลิก</button>
										</form>
										{{else}}
										<span class="text-muted small">-</span>
										{{end}}
									</td>
								</tr>
								{{else}}
								<tr>
									<td colspan="7" class="text-center py-4 text-muted">
										<i class="fa-solid fa-mug-hot fa-2x mb-2 d-block opacity-50"></i>คุณยังไม่มีรายการสั่งซื้อเครื่องดื่ม
									</td>
								</tr>
								{{end}}
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</div>
</body>
</html>
{{end}}

{{define "admin.html"}}
<!DOCTYPE html>
<html lang="th">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Admin Panel - ระบบจัดการร้าน Fresh Drinks Cafe</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
	<nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm">
		<div class="container">
			<a class="navbar-brand fw-bold text-warning" href="/admin"><i class="fa-solid fa-store me-2"></i>ระบบจัดการร้าน Fresh Drinks Cafe (Barista / Admin View)</a>
			<div class="d-flex align-items-center text-white">
				<span class="me-3">ผู้ดูแลระบบ: <b>{{.Username}}</b></span>
				<a href="/dashboard" class="btn btn-outline-light btn-sm me-2"><i class="fa-solid fa-arrow-left me-1"></i>กลับหน้าลูกค้า</a>
				<a href="/logout" class="btn btn-danger btn-sm"><i class="fa-solid fa-right-from-bracket me-1"></i>ออกจากระบบ</a>
			</div>
		</div>
	</nav>

	<div class="container my-4">
		<div class="row g-3 mb-4">
			<div class="col-md-4">
				<div class="card border-0 shadow-sm rounded-4 p-3 bg-white border-start border-primary border-4">
					<div class="d-flex align-items-center justify-content-between">
						<div>
							<div class="text-muted small">สมาชิกในระบบ</div>
							<h3 class="fw-bold mb-0 text-primary">{{.TotalUsers}} คน</h3>
						</div>
						<i class="fa-solid fa-users fa-2x text-primary opacity-50"></i>
					</div>
				</div>
			</div>
			<div class="col-md-4">
				<div class="card border-0 shadow-sm rounded-4 p-3 bg-white border-start border-success border-4">
					<div class="d-flex align-items-center justify-content-between">
						<div>
							<div class="text-muted small">คำสั่งซื้อทั้งหมด</div>
							<h3 class="fw-bold mb-0 text-success">{{.TotalOrders}} รายการ</h3>
						</div>
						<i class="fa-solid fa-glass-water fa-2x text-success opacity-50"></i>
					</div>
				</div>
			</div>
			<div class="col-md-4">
				<div class="card border-0 shadow-sm rounded-4 p-3 bg-white border-start border-warning border-4">
					<div class="d-flex align-items-center justify-content-between">
						<div>
							<div class="text-muted small">ยอดขายรวมทั้งหมด</div>
							<h3 class="fw-bold mb-0 text-warning">{{.TotalRevenue}} บาท</h3>
						</div>
						<i class="fa-solid fa-sack-dollar fa-2x text-warning opacity-50"></i>
					</div>
				</div>
			</div>
		</div>

		<div class="card border-0 shadow-sm rounded-4 p-4">
			<h5 class="fw-bold mb-3"><i class="fa-solid fa-list-check me-2 text-danger"></i>รายการสั่งซื้อทั้งหมดของลูกค้า (Barista Order Management)</h5>
			<div class="table-responsive">
				<table class="table table-hover align-middle">
					<thead class="table-dark">
						<tr>
							<th>รหัส</th>
							<th>ลูกค้า</th>
							<th>เมนูที่สั่ง</th>
							<th>จำนวน</th>
							<th>ราคารวม</th>
							<th>สถานะปัจจุบัน</th>
							<th class="text-center">อัปเดตสถานะการชง</th>
						</tr>
					</thead>
					<tbody>
						{{range .Orders}}
						<tr>
							<td class="fw-bold">#ORD-{{.ID}}</td>
							<td><span class="badge bg-secondary"><i class="fa-solid fa-user me-1"></i>{{.OwnerName}}</span></td>
							<td class="fw-semibold">
								{{.ItemName}}
								{{if .Note}}<div class="text-muted small">({{.Note}})</div>{{end}}
							</td>
							<td class="text-center">{{.Quantity}} แก้ว</td>
							<td class="fw-bold text-success">{{.TotalPrice}} ฿</td>
							<td>
								{{if eq .Status "pending"}}
									<span class="badge bg-secondary">Pending</span>
								{{else if or (eq .Status "baking") (eq .Status "brewing")}}
									<span class="badge bg-warning text-dark">Brewing</span>
								{{else if eq .Status "completed"}}
									<span class="badge bg-success">Completed</span>
								{{else}}
									<span class="badge bg-danger">Cancelled</span>
								{{end}}
							</td>
							<td class="text-center">
								<form method="POST" action="/admin" class="d-flex justify-content-center gap-1">
									<input type="hidden" name="order_id" value="{{.ID}}">
									<select name="status" class="form-select form-select-sm" style="width: 150px;">
										<option value="pending" {{if eq .Status "pending"}}selected{{end}}>1. รอยืนยัน</option>
										<option value="baking" {{if or (eq .Status "baking") (eq .Status "brewing")}}selected{{end}}>2. กำลังชงเครื่องดื่ม</option>
										<option value="completed" {{if eq .Status "completed"}}selected{{end}}>3. เสร็จพร้อมเสิร์ฟ</option>
										<option value="cancelled" {{if eq .Status "cancelled"}}selected{{end}}>4. ยกเลิก</option>
									</select>
									<button type="submit" class="btn btn-sm btn-primary"><i class="fa-solid fa-save"></i> บันทึก</button>
								</form>
							</td>
						</tr>
						{{else}}
						<tr>
							<td colspan="7" class="text-center py-4 text-muted">ยังไม่มีรายการสั่งซื้อเข้ามาในระบบ</td>
						</tr>
						{{end}}
					</tbody>
				</table>
			</div>
		</div>
	</div>
</body>
</html>
{{end}}
`
