package rules

default allow = false

users := {
	"alice": {"manager": "charlie", "title": "salesperson"},
	"bob": {"manager": "charlie", "title": "salesperson"},
	"charlie": {"manager": "dave", "title": "manager"},
	"dave": {"manager": null, "title": "ceo"},
}

user_is_employee {
    users[input.user]
}

user_is_manager {
    users[input.user].title != "salesperson"
}

allow {
    # anyone can read cars
	input.method == "GET"
	input.path == ["cars"]
}

allow {
    # only managers can create new cars
    user_is_manager
    input.method == "POST"
    input.method == ["cars"]
}

allow {
    # only employees can GET /cars/{carid}
    user_is_employee
	input.method == "GET"
	input.path == ["cars", carid]
}