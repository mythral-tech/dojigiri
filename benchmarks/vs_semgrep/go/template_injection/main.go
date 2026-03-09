package main

import (
	"html/template"
	"net/http"
)

var tmpl = template.Must(template.New("page").Parse(`
<!DOCTYPE html>
<html>
<head><title>{{.Title}}</title></head>
<body>
  <h1>{{.Title}}</h1>
  <div class="content">{{.Content}}</div>
  <div class="bio">{{.Bio}}</div>
</body>
</html>
`))

type PageData struct {
	Title   string
	Content template.HTML
	Bio     template.HTML
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	bio := r.URL.Query().Get("bio")

	data := PageData{
		Title:   username,
		Content: template.HTML("<p>Welcome to your profile</p>"),
		Bio:     template.HTML(bio),
	}

	tmpl.Execute(w, data)
}

func main() {
	http.HandleFunc("/profile", profileHandler)
	http.ListenAndServe(":8080", nil)
}
