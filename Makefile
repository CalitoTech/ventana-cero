.PHONY: run ui demo test eval all
demo:       ## demo en vivo: mismo ataque, 200 sin Ventana Cero y 403 con ella (puerto 8001)
	python -m ventana_cero.demo
run:        ## corre el lazo de punta a punta
	python -m ventana_cero
ui:         ## panel en vivo: el boton corre el lazo real (puerto 8000)
	python -m ventana_cero.server
test:       ## prueba de humo del lazo
	python -m unittest discover -s tests
eval:       ## metricas sobre los fixtures
	python eval/run_eval.py
all: test run eval
