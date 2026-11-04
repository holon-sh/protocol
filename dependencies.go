package protocol

func Dependencies(apps []App) []string {
	var problems []string
	byName := make(map[string]App, len(apps))
	for _, app := range apps {
		byName[app.Name] = app
	}
	for _, app := range apps {
		variables := map[string]bool{}
		for _, target := range app.Requires {
			variable := DependencyEnvName(target)
			if !ValidAppName(target) || target == app.Name {
				problems = append(problems, "invalid dependency or self-reference: "+app.Name)
			}
			if _, ok := byName[target]; !ok {
				problems = append(problems, "dependency "+app.Name+"."+target+" has no runtime")
			}
			if _, exists := app.Env[variable]; variables[variable] || exists {
				problems = append(problems, "conflicting dependency environment: "+app.Name+"."+variable)
			}
			variables[variable] = true
		}
	}
	visiting := map[string]bool{}
	visited := map[string]bool{}
	var visit func(string)
	visit = func(name string) {
		if visiting[name] {
			problems = append(problems, "dependency graph contains a cycle")
			return
		}
		if visited[name] {
			return
		}
		visiting[name] = true
		for _, target := range byName[name].Requires {
			visit(target)
		}
		delete(visiting, name)
		visited[name] = true
	}
	for name := range byName {
		visit(name)
	}
	return problems
}
