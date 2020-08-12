#import "ViewController.h"
#import "JailbreakDetection.h"

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UILabel *detect_label;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}


- (IBAction)Verify_Button:(UIButton *)sender {
    if([JailbreakDetection isJailbreak] == true){
        _detect_label.text = @"Detected!";
    }else{
        _detect_label.text = @"Not Detected!";
    }
}


@end
