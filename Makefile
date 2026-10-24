.PHONY: run ui test eval all
run:        ## corre el lazo de punta a punta
	python -m ventana_cero
ui:         ## sirve el panel de la demo
	python -m http.server -d ui/public
test:       ## prueba de humo del lazo
	python -m unittest discover -s tests
eval:       ## metricas sobre los fixtures
	python eval/run_eval.py
all: test run eval
