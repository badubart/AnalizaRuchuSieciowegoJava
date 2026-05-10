package analizasieci;

import analizasieci.windowsControls.WindowManager;
import javafx.stage.Stage;
import javafx.application.Application;

public class Main extends Application {
    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        Solution program = new Solution();
        program.launch();

        WindowManager window = new WindowManager();
        window.showDevSelectWindow(program);
    }
}