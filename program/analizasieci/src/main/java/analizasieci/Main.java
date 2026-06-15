package analizasieci;

import analizasieci.windowsControls.WindowManager;
import javafx.stage.Stage;
import javafx.application.Application;

/**
 * Punkt wejścia aplikacji JavaFX.
 * Tworzy obiekt {@link Solution} (logikę programu) i otwiera pierwsze okno –
 * wybór interfejsu sieciowego.
 */
public class Main extends Application {
    /**
     * Standardowe wejście Javy – uruchamia aplikację JavaFX.
     *
     * @param args argumenty wiersza poleceń (nieużywane)
     */
    public static void main(String[] args) {
        launch(args);
    }

    /**
     * Metoda cyklu życia JavaFX – wywoływana po starcie platformy.
     * Otwiera okno wyboru interfejsu sieciowego.
     *
     * @param primaryStage główne okno dostarczone przez JavaFX (nieużywane bezpośrednio)
     */
    @Override
    public void start(Stage primaryStage) {
        Solution program = new Solution();

        WindowManager window = new WindowManager();
        window.showDevSelectWindow(program);
    }
}